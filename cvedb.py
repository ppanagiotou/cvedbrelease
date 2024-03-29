# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Handling CVE database
"""
from __future__ import annotations

import asyncio
import datetime
import json
import logging
import shutil
import sqlite3
from os import utime
from pathlib import Path
from typing import Any

import requests
from rich.progress import track

from cve_bin_tool.async_utils import run_coroutine
from data_sources import curl_source, gad_source, nvd_source, osv_source, redhat_source, rsd_source
from cve_bin_tool.error_handler import CVEDBError, ErrorMode
from cve_bin_tool.fetch_json_db import Fetch_JSON_DB
from cve_bin_tool.log import LOGGER
from cve_bin_tool.version import check_latest_version

import sys
import argparse

logging.basicConfig(level=logging.DEBUG)

# database defaults
DISK_LOCATION_DEFAULT = Path("~").expanduser() / ".cache" / "cvedbrelease"
DISK_LOCATION_BACKUP = Path("~").expanduser() / ".cache" / "cvedbrelease-backup"
DBNAME = "cve.db"
OLD_CACHE_DIR = Path("~") / ".cache" / "cvedb"


class CVEDB:
    """
    Retrieves CVE data from data sources and handles CVE Database.
    The sources can be found in the cve_bin_tool/data_sources/ directory.
    """

    CACHEDIR = DISK_LOCATION_DEFAULT
    BACKUPCACHEDIR = DISK_LOCATION_BACKUP
    LOGGER = logging.getLogger("cvedb")
    SOURCES = [
        nvd_source.NVD_Source,
        curl_source.Curl_Source,
        osv_source.OSV_Source,
        gad_source.GAD_Source,
        redhat_source.REDHAT_Source,
        rsd_source.RSD_Source,
    ]

    def __init__(
            self,
            sources=None,
            cachedir: str | None = None,
            backup_cachedir: str | None = None,
            version_check: bool = True,
            error_mode: ErrorMode = ErrorMode.TruncTrace,
            nvd_api_key: str = ""
    ):

        self.sources = (
            sources
            if sources is not None
            else [x(error_mode=error_mode) for x in self.SOURCES]
        )

        self.sources[0].nvd_api_key = nvd_api_key

        self.cachedir = Path(cachedir) if cachedir is not None else self.CACHEDIR
        self.backup_cachedir = (
            Path(backup_cachedir)
            if backup_cachedir is not None
            else self.BACKUPCACHEDIR
        )
        self.error_mode = error_mode

        # Will be true if refresh was successful
        self.was_updated = False

        # version update
        self.version_check = version_check

        # set up the db if needed
        self.dbpath = self.cachedir / DBNAME
        self.connection: sqlite3.Connection | None = None

        self.data = []
        self.cve_count = -1
        self.all_cve_entries: list[dict[str, Any]] | None = None

        self.exploits_list = []
        self.exploit_count = 0

        if not self.dbpath.exists():
            self.rollback_cache_backup()

    def get_cve_count(self) -> int:
        if self.cve_count == -1:
            # Force update
            self.check_cve_entries()
        return self.cve_count

    def check_db_exists(self) -> bool:
        return self.dbpath.is_file()

    def get_db_update_date(self) -> float:
        # last time when CVE data was updated
        self.time_of_last_update = datetime.datetime.fromtimestamp(
            self.dbpath.stat().st_mtime
        )
        return self.dbpath.stat().st_mtime

    async def refresh(self) -> None:
        """Refresh the cve database and check for new version."""
        # refresh the database
        if not self.cachedir.is_dir():
            self.cachedir.mkdir(parents=True)

        # check for the latest version
        if self.version_check:
            check_latest_version()

        await self.get_data()

    def refresh_cache_and_update_db(self) -> None:
        self.LOGGER.debug("Updating CVE data. This will take a few minutes.")
        # refresh the nvd cache
        run_coroutine(self.refresh())

        # if the database isn't open, open it
        self.init_database()
        self.populate_db()

    def get_cvelist_if_stale(self) -> None:
        """Update if the local db is more than one day old.
        This avoids the full slow update with every execution.
        """
        if not self.dbpath.is_file() or (
                datetime.datetime.today()
                - datetime.datetime.fromtimestamp(self.dbpath.stat().st_mtime)
        ) > datetime.timedelta(hours=24):
            self.refresh_cache_and_update_db()
            self.time_of_last_update = datetime.datetime.today()
        else:
            self.time_of_last_update = datetime.datetime.fromtimestamp(
                self.dbpath.stat().st_mtime
            )
            self.LOGGER.info(
                "Using cached CVE data (<24h old). Use -u now to update immediately."
            )
            self.db_open()
            if not self.latest_schema(self.connection.cursor()):
                self.refresh_cache_and_update_db()
                self.time_of_last_update = datetime.datetime.today()
            else:
                self.db_close()

    def latest_schema(self, cursor: sqlite3.Cursor) -> bool:
        """Check database is using latest schema"""
        self.LOGGER.debug("Check database is using latest schema")
        schema_check = "SELECT * FROM cve_severity WHERE 1=0"
        result = cursor.execute(schema_check)
        schema_latest = False
        # Look through column names and check for column added in latest schema
        for col_name in result.description:
            if col_name[0] == "data_source":
                schema_latest = True
        return schema_latest

    def check_cve_entries(self) -> bool:
        """Report if database has some CVE entries"""
        self.db_open()
        cursor = self.connection.cursor()
        cve_entries_check = "SELECT COUNT(*) FROM cve_severity"
        cursor.execute(cve_entries_check)
        # Find number of entries
        cve_entries = cursor.fetchone()[0]
        self.LOGGER.info(f"There are {cve_entries} CVE entries in the database")
        self.db_close()
        self.cve_count = cve_entries
        return cve_entries > 0

    async def get_data(self):
        """Get CVE data from datasources"""
        tasks = []

        for source in self.sources:
            if source is not None:
                tasks.append(source.get_cve_data())

        for r in await asyncio.gather(*tasks):
            self.data.append(r)

    def init_database(self) -> None:
        """Initialize db tables used for storing cve/version data"""
        self.db_open()
        cursor = self.connection.cursor()

        cve_data_create = """
        CREATE TABLE IF NOT EXISTS cve_severity (
            cve_number TEXT,
            severity TEXT,
            description TEXT,
            score INTEGER,
            cvss_version INTEGER,
            cvss_vector TEXT,
            data_source TEXT,
            publishdate DATE,
            PRIMARY KEY(cve_number, data_source)
        )
        """
        version_range_create = """
        CREATE TABLE IF NOT EXISTS cve_range (
            cve_number TEXT,
            vendor TEXT,
            product TEXT,
            version TEXT,
            versionStartIncluding TEXT,
            versionStartExcluding TEXT,
            versionEndIncluding TEXT,
            versionEndExcluding TEXT,
            FOREIGN KEY(cve_number) REFERENCES cve_severity(cve_number)
        )
        """
        index_range = "CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)"
        cursor.execute(cve_data_create)
        cursor.execute(version_range_create)
        cursor.execute(index_range)

        if not self.latest_schema(cursor):
            # Recreate table using latest schema
            self.LOGGER.info("Upgrading database to latest schema")
            cursor.execute("DROP TABLE cve_severity")
            cursor.execute(cve_data_create)
        self.connection.commit()

        self.db_close()

    def populate_db(self) -> None:
        """Function that populates the database from the JSON.
        WARNING: After some inspection of the data, we are assuming that start/end ranges are kept together
        in single nodes.  This isn't *required* by the json so may not be true everywhere.  If that's the case,
        we'll need a better parser to match those together.
        """

        for idx, data in enumerate(self.data):
            _, source_name = data

            if source_name == "NVD":
                self.data.insert(0, self.data.pop(idx))
                break

        for cve_data, source_name in self.data:

            if source_name != "NVD" and cve_data[0] is not None:
                cve_data = self.update_vendors(cve_data)
                cve_data = self.filter_duplicate(cve_data, source_name)

            severity_data, affected_data = cve_data

            self.db_open()
            cursor = self.connection.cursor()

            if severity_data is not None:
                self.populate_severity(severity_data, cursor, data_source=source_name)
            if affected_data is not None:
                self.populate_affected(
                    affected_data,
                    cursor,
                )

            self.connection.commit()
            self.db_close()

    def populate_severity(self, severity_data, cursor, data_source):
        cve_severity = """
        cve_severity(
            CVE_number,
            severity,
            description,
            score,
            cvss_version,
            cvss_vector,
            data_source,
            publishdate
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """

        insert_severity = f"INSERT or REPLACE INTO {cve_severity}"
        del_cve_range = "DELETE from cve_range where CVE_number=?"

        for cve in severity_data:
            # Check no None values
            if not bool(cve.get("severity")):
                LOGGER.debug(f"Update severity for {cve['ID']} {data_source}")
                cve["severity"] = "unknown"
            if not bool(cve.get("description")):
                LOGGER.debug(f"Update description for {cve['ID']} {data_source}")
                cve["description"] = "unknown"

            if not bool(cve.get("score")):
                LOGGER.debug(f"Update score for {cve['ID']} {data_source}")
                cve["score"] = None
            else:
                if str(cve.get("score")) == 'unknown':
                    cve["score"] = None

            if not bool(cve.get("CVSS_version")):
                LOGGER.debug(f"Update CVSS version for {cve['ID']} {data_source}")
                cve["CVSS_version"] = None
            else:
                if str(cve.get("CVSS_version")) == 'unknown':
                    cve["CVSS_version"] = None

            if not bool(cve.get("CVSS_vector")):
                LOGGER.debug(f"Update CVSS Vector for {cve['ID']} {data_source}")
                cve["CVSS_vector"] = "unknown"

            if not bool(cve.get("publishedDate")):
                LOGGER.debug(f"Update publishedDate for {cve['ID']} {data_source}")
                logging.info(f"Update publishedDate for {cve['ID']} {data_source}")
                cve["publishedDate"] = None

        for cve in severity_data:

            if str(cve.get("description")).__contains__("** REJECT **"):
                logging.info(f"Do not add this CVE [** REJECT **] - {cve}")
                continue

            try:
                cursor.execute(
                    insert_severity,
                    [
                        cve["ID"],
                        cve["severity"].upper(),
                        cve["description"],
                        cve["score"],
                        cve["CVSS_version"],
                        cve["CVSS_vector"],
                        data_source,
                        cve["publishedDate"],
                    ],
                )
            except Exception as e:
                logging.error(f"Unable to insert data for {data_source} - {e}\n{cve}")

        # Delete any old range entries for this CVE_number
        cursor.executemany(del_cve_range, [(cve["ID"],) for cve in severity_data])

    def populate_affected(self, affected_data, cursor):

        insert_cve_range = """
        INSERT or REPLACE INTO cve_range(
            cve_number,
            vendor,
            product,
            version,
            versionStartIncluding,
            versionStartExcluding,
            versionEndIncluding,
            versionEndExcluding
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """

        cursor.executemany(
            insert_cve_range,
            [
                (
                    affected["cve_id"],
                    affected["vendor"],
                    affected["product"],
                    affected["version"],
                    affected["versionStartIncluding"],
                    affected["versionStartExcluding"],
                    affected["versionEndIncluding"],
                    affected["versionEndExcluding"],
                )
                for affected in affected_data
            ],
        )

    def clear_cached_data(self) -> None:
        self.create_cache_backup()
        if self.cachedir.exists():
            self.LOGGER.warning(f"Updating cachedir {self.cachedir}")
            shutil.rmtree(self.cachedir)
        # Remove files associated with pre-1.0 development tree
        if OLD_CACHE_DIR.exists():
            self.LOGGER.warning(f"Deleting old cachedir {OLD_CACHE_DIR}")
            shutil.rmtree(OLD_CACHE_DIR)

    def get_vendor_product_pairs(self, package_names) -> list[dict[str, str]]:
        """
        Fetches vendor from the database for packages that doesn't have vendor info for Package List Parser Utility and Universal Python package checker.
        """
        self.db_open()
        cursor = self.connection.cursor()
        vendor_package_pairs = []
        query = """
        SELECT DISTINCT vendor FROM cve_range
        WHERE product=?
        """

        # For python package checkers we don't need the progress bar running
        if type(package_names) != list:
            cursor.execute(query, [package_names])
            vendors = list(map(lambda x: x[0], cursor.fetchall()))

            for vendor in vendors:
                if vendor != "":
                    vendor_package_pairs.append(
                        {
                            "vendor": vendor,
                            "product": package_names,
                        }
                    )
            if len(vendor_package_pairs) > 1:
                self.LOGGER.debug(f"Multiple vendors found for {package_names}")
                for entry in vendor_package_pairs:
                    self.LOGGER.debug(f'{entry["product"]} - {entry["vendor"]}')
        else:
            for package_name in track(
                    package_names, description="Processing the given list...."
            ):
                cursor.execute(query, [package_name["name"].lower()])
                vendors = list(map(lambda x: x[0], cursor.fetchall()))
                for vendor in vendors:
                    if vendor != "":
                        vendor_package_pairs.append(
                            {
                                "vendor": vendor,
                                "product": package_name["name"],
                            }
                        )
        self.db_close()

        return vendor_package_pairs

    def update_vendors(self, cve_data):
        """Get vendors for products and update CVE data."""
        updated_severity = []
        updated_affected = []

        severity_data, affected_data = cve_data

        self.db_open()

        cursor = self.connection.cursor()

        create_index = "CREATE INDEX IF NOT EXISTS product_vendor_index ON cve_range (product, vendor)"
        drop_index = "DROP INDEX product_vendor_index"

        query = """
        SELECT DISTINCT vendor FROM cve_range
        WHERE product=?
        """

        cursor.execute(create_index)

        sel_cve = set()

        for affected in affected_data:
            cursor.execute(query, [affected["product"]])
            vendors = list(map(lambda x: x[0], cursor.fetchall()))

            if len(vendors) == 1:
                affected["vendor"] = vendors[0]
            else:
                for vendor in vendors:
                    if vendor == affected["vendor"]:
                        updated_affected.append(affected)
                        sel_cve.add(affected["cve_id"])
                continue

            updated_affected.append(affected)
            sel_cve.add(affected["cve_id"])

        for cve in severity_data:
            if cve["ID"] in sel_cve:
                updated_severity.append(cve)

        cursor.execute(drop_index)

        self.db_close()

        return updated_severity, updated_affected

    def filter_duplicate(self, cve_data, source):
        """Filter out duplicate CVEs in CVE data."""
        updated_severity = []
        updated_affected = []

        severity_data, affected_data = cve_data

        self.db_open()

        cursor = self.connection.cursor()

        query = """
        SELECT cve_number, data_source FROM cve_severity
        WHERE cve_number=?
        """

        sel_cve = set()

        for affected in affected_data:
            cursor.execute(query, [affected["cve_id"]])
            result = cursor.fetchall()
            cve = list(map(lambda x: x[0], result))

            if len(cve) == 0 or result[0][1] == source:
                updated_affected.append(affected)
                sel_cve.add(affected["cve_id"])

        for cve in severity_data:
            if cve["ID"] in sel_cve:
                updated_severity.append(cve)

        self.db_close()

        return updated_severity, updated_affected

    def db_open(self) -> None:
        """Opens connection to sqlite database."""
        if not self.connection:
            self.connection = sqlite3.connect(self.dbpath)

    def db_close(self) -> None:
        """Closes connection to sqlite database."""
        if self.connection:
            self.connection.close()
            self.connection = None

    def create_cache_backup(self) -> None:
        """Creates a backup of the cachedir in case anything fails"""
        if self.cachedir.exists():
            self.LOGGER.debug(
                f"Creating backup of cachedir {self.cachedir} at {self.backup_cachedir}"
            )
            self.remove_cache_backup()
            shutil.copytree(self.cachedir, self.backup_cachedir)

    def copy_db(self, filename, export=True):
        self.db_close()
        if export:
            shutil.copy(self.dbpath, filename)
        else:
            shutil.copy(filename, self.dbpath)

    def remove_cache_backup(self) -> None:
        """Removes the backup if database was successfully loaded"""
        if self.backup_cachedir.exists():
            self.LOGGER.debug(f"Removing backup cache from {self.backup_cachedir}")
            shutil.rmtree(self.backup_cachedir)

    def rollback_cache_backup(self) -> None:
        """Rollback the cachedir backup in case anything fails"""
        if (self.backup_cachedir / DBNAME).exists():
            self.LOGGER.info("Rolling back the cache to its previous state")
            if self.cachedir.exists():
                shutil.rmtree(self.cachedir)
            shutil.move(self.backup_cachedir, self.cachedir)

    def __del__(self) -> None:
        self.rollback_cache_backup()

    # Methods to check and update exploits

    def update_exploits(self):
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        r = requests.get(url)
        data = r.json()
        cves = data["vulnerabilities"]
        exploit_list = []
        for cve in cves:
            exploit_list.append((cve["cveID"], cve["product"], cve["shortDescription"]))
        self.populate_exploit_db(exploit_list)

    def get_cache_exploits(self):
        get_exploits = """
        SELECT cve_number FROM cve_exploited
        """
        self.db_open()
        cursor = self.connection.cursor()
        cursor.row_factory = lambda cursor, row: row[0]
        self.exploits_list = cursor.execute(get_exploits).fetchall()
        self.db_close()
        self.exploit_count = len(self.exploits_list)

    def get_exploits_list(self):
        return self.exploits_list

    def get_exploits_count(self):
        return self.exploit_count

    def create_exploit_db(self):
        create_exploit_table = """
        CREATE TABLE IF NOT EXISTS cve_exploited (
            cve_number TEXT,
            product TEXT,
            description TEXT,
            PRIMARY KEY(cve_number)
        )
        """
        self.db_open()
        cursor = self.connection.cursor()
        cursor.execute(create_exploit_table)
        self.connection.commit()
        self.db_close()

    def populate_exploit_db(self, exploits):
        insert_exploit = """
        INSERT or REPLACE INTO cve_exploited (
            cve_number,
            product,
            description
        )
        VALUES (?,?,?)
        """
        self.db_open()
        cursor = self.connection.cursor()
        cursor.executemany(insert_exploit, exploits)
        self.connection.commit()
        self.db_close()

    def get_cves(self, lcve_number):

        self.db_open()

        cursor = self.connection.cursor()

        query = """SELECT cve_number, publishdate, score, cvss_version FROM cve_severity WHERE cve_number = ?"""
        cvedict = dict()
        for cve_number in lcve_number:
            cursor.execute(query, [cve_number])
            for cve_res in cursor:
                cvedict[cve_res[0]] = {"publishdate": cve_res[1], "score": cve_res[2], "cvss_version": cve_res[3]}

        return cvedict


def getOptions(args=None):
    if args is None:
        args = sys.argv[1:]
    parser = argparse.ArgumentParser(description="Parses command.")
    parser.add_argument("-u", "--update", help="Update CVE database.", dest='update', action="store_true",
                        default=False)
    parser.add_argument("-s", "--search", help="Search for a CVE. Example: -s CVE-2018-0539 -s CVE-2018-0541",
                        dest='cve_number', action='append')
    parser.add_argument("--nvd-api-key", "--nvd-api-key", help="NVD API KEY", dest='nvd_api_key', default="")
    options = parser.parse_args(args)
    return options


if __name__ == "__main__":

    # parse arguments
    options = getOptions()

    cvedb = CVEDB(nvd_api_key=options.nvd_api_key)

    if options.update:
        cvedb.clear_cached_data()
        cvedb.refresh_cache_and_update_db()

    if options.cve_number is not None:
        resdict = cvedb.get_cves(options.cve_number)
        print(json.dumps(resdict))
    else:
        print("{}")

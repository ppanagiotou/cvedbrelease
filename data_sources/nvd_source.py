# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import datetime
import glob
import gzip
import hashlib
import json
import logging
import parser
import re
import sqlite3
from pathlib import Path
from typing import Any

import aiohttp
from rich.progress import track

from cve_bin_tool.async_utils import FileIO, GzipFile, RateLimiter
from data_sources import (
    DBNAME,
    DISK_LOCATION_BACKUP,
    DISK_LOCATION_DEFAULT,
    NVD_FILENAME_TEMPLATE,
    Data_Source,
)
from cve_bin_tool.error_handler import (
    AttemptedToWriteOutsideCachedir,
    CVEDataForYearNotInCache,
    ErrorHandler,
    ErrorMode,
    NVDRateLimit,
    SHAMismatch,
)
from cve_bin_tool.log import LOGGER
from cve_bin_tool.nvd_api import NVD_API

logging.basicConfig(level=logging.DEBUG)


class NVD_Source(Data_Source):
    """
    Downloads NVD data in json form and stores it on disk in a cache.
    """

    SOURCE = "NVD"
    CACHEDIR = DISK_LOCATION_DEFAULT
    BACKUPCACHEDIR = DISK_LOCATION_BACKUP
    FEED = "https://nvd.nist.gov/vuln/data-feeds"
    LOGGER = LOGGER.getChild("CVEDB")
    NVDCVE_FILENAME_TEMPLATE = NVD_FILENAME_TEMPLATE
    META_LINK = "https://nvd.nist.gov"
    META_REGEX = re.compile(r"\/feeds\/json\/.*-[0-9]*\.[0-9]*-[0-9]*\.meta")
    RANGE_UNSET = ""

    def __init__(
        self,
        feed: str | None = None,
        session: RateLimiter | None = None,
        error_mode: ErrorMode = ErrorMode.TruncTrace,
        nvd_type: str = "json",
        incremental_update: bool = False,
        nvd_api_key: str = "",
    ):
        self.feed = feed if feed is not None else self.FEED
        self.cachedir = self.CACHEDIR
        self.backup_cachedir = self.BACKUPCACHEDIR
        self.error_mode = error_mode
        self.source_name = self.SOURCE

        # set up the db if needed
        self.dbpath = str(Path(self.cachedir) / DBNAME)
        self.connection: sqlite3.Connection | None = None
        self.session = session
        self.cve_count = -1
        self.nvd_type = nvd_type
        self.incremental_update = incremental_update
        self.all_cve_entries: list[dict[str, Any]] | None = None

        # store the nvd api key for use later
        self.nvd_api_key = nvd_api_key

    async def get_cve_data(self):
        await self.fetch_cves()

        if self.nvd_type == "api":
            return self.format_data(self.all_cve_entries), self.source_name
        else:
            severity_data = []
            affected_data = []
            years = self.nvd_years()
            for year in years:
                severity, affected = self.format_data(
                    self.load_nvd_year(year)["CVE_Items"]
                )
                severity_data.extend(severity)
                affected_data.extend(affected)

            return (severity_data, affected_data), self.source_name

    def format_data(self, all_cve_entries):
        """Format CVE data for CVEDB"""

        cve_data = []
        affects_data = []

        for cve_item in all_cve_entries:
            # the information we want:
            # CVE ID, Severity, Score ->
            # affected {Vendor(s), Product(s), Version(s)}

            cve = {
                "ID": cve_item["cve"]["CVE_data_meta"]["ID"],
                "description": cve_item["cve"]["description"]["description_data"][0][
                    "value"
                ],
                "severity": "unknown",
                "score": "unknown",
                "CVSS_version": "unknown",
                "CVSS_vector": "unknown",
                "publishedDate": datetime.datetime.fromisoformat(cve_item["publishedDate"].replace("Z", "+00:00"))
            }
            if cve["description"].startswith("** REJECT **"):
                # Skip this CVE if it's marked as 'REJECT'
                continue

            # Get CVSSv3 or CVSSv2 score for output.
            # Details are left as an exercise to the user.
            if "baseMetricV3" in cve_item["impact"]:
                cve["severity"] = cve_item["impact"]["baseMetricV3"]["cvssV3"][
                    "baseSeverity"
                ]
                cve["score"] = cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                cve["CVSS_vector"] = cve_item["impact"]["baseMetricV3"]["cvssV3"][
                    "vectorString"
                ]
                cve["CVSS_version"] = 3
            elif "baseMetricV2" in cve_item["impact"]:
                cve["severity"] = cve_item["impact"]["baseMetricV2"]["severity"]
                cve["score"] = cve_item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                cve["CVSS_vector"] = cve_item["impact"]["baseMetricV2"]["cvssV2"][
                    "vectorString"
                ]
                cve["CVSS_version"] = 2

            cve_data.append(cve)

            # walk the nodes with version data
            # return list of versions
            affects_list = []
            if "configurations" in cve_item:
                for node in cve_item["configurations"]["nodes"]:
                    affects_list.extend(self.parse_node(node))
                    if "children" in node:
                        for child in node["children"]:
                            affects_list.extend(self.parse_node(child))

            for affects in affects_list:
                affects["cve_id"] = cve["ID"]

            affects_data.extend(affects_list)

        return cve_data, affects_data

    def parse_node(self, node: dict[str, Any]) -> list[dict[str, str]]:
        affects_list = []
        if "cpe_match" in node:
            for cpe_match in node["cpe_match"]:
                cpe_split = cpe_match["cpe23Uri"].split(":")
                affects = {
                    "vendor": cpe_split[3],
                    "product": cpe_split[4],
                    "version": cpe_split[5],
                }

                # if we have a range (e.g. version is *) fill it out, and put blanks where needed
                range_fields = [
                    "versionStartIncluding",
                    "versionStartExcluding",
                    "versionEndIncluding",
                    "versionEndExcluding",
                ]
                for field in range_fields:
                    if field in cpe_match:
                        affects[field] = cpe_match[field]
                    else:
                        affects[field] = self.RANGE_UNSET

                affects_list.append(affects)
        return affects_list

    async def fetch_cves(self):
        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=19)
            self.session = RateLimiter(
                aiohttp.ClientSession(connector=connector, trust_env=True)
            )

        tasks = []
        if self.nvd_type == "api":
            self.LOGGER.info("[Using NVD API]")
            self.all_cve_entries = await asyncio.create_task(
                self.nist_fetch_using_api(),
            )

        else:
            self.LOGGER.info("Downloading CVE data...")
            nvd_metadata = await asyncio.create_task(
                self.nist_scrape(self.session),
            )

            tasks = [
                self.cache_update(self.session, url, meta["sha256"])
                for url, meta in nvd_metadata.items()
                if meta is not None
            ]

        total_tasks = len(tasks)

        # error_mode.value will only be greater than 1 if quiet mode.
        if self.error_mode.value > 1 and self.nvd_type == "json":
            iter_tasks = track(
                asyncio.as_completed(tasks),
                description="Downloading CVEs...",
                total=total_tasks,
            )
        else:
            iter_tasks = asyncio.as_completed(tasks)

        for task in iter_tasks:
            await task

        await self.session.close()
        self.session = None

    async def nist_fetch_using_api(self) -> list:
        """Fetch using NVD's CVE API (as opposed to NVD's JSON Vulnerability Feeds)"""

        from cve_bin_tool import cvedb  # prevent cyclic import

        db = cvedb.CVEDB()

        nvd_api = NVD_API(
            logger=self.LOGGER,
            error_mode=self.error_mode,
            incremental_update=self.incremental_update,
            api_key=self.nvd_api_key,
        )
        if self.incremental_update:
            await nvd_api.get_nvd_params(
                time_of_last_update=datetime.datetime.fromtimestamp(
                    db.get_db_update_date()
                )
            )
        else:
            await nvd_api.get_nvd_params()
        await nvd_api.get()
        await nvd_api.session.close()
        nvd_api.session = None
        return nvd_api.all_cve_entries

    async def getmeta(
        self, session: RateLimiter, meta_url: str
    ) -> tuple[str, dict[str, str]]:
        async with await session.get(meta_url) as response:
            response.raise_for_status()
            return (
                meta_url.replace(".meta", ".json.gz"),
                dict(
                    [
                        line.split(":", maxsplit=1)
                        for line in (await response.text()).splitlines()
                        if ":" in line
                    ]
                ),
            )

    async def nist_scrape(self, session: RateLimiter):
        async with await session.get(self.feed) as response:
            response.raise_for_status()
            page = await response.text()
            json_meta_links = self.META_REGEX.findall(page)
            return dict(
                await asyncio.gather(
                    *(
                        self.getmeta(session, f"{self.META_LINK}{meta_url}")
                        for meta_url in json_meta_links
                    )
                )
            )

    async def cache_update(
        self,
        session: RateLimiter,
        url: str,
        sha: str,
        chunk_size: int = 16 * 1024,
    ) -> None:
        """
        Update the cache for a single year of NVD data.
        """
        filename = url.split("/")[-1]
        # Ensure we only write to files within the cachedir
        cache_path = Path(self.cachedir)
        filepath = Path(str(cache_path / filename)).resolve()
        if not str(filepath).startswith(str(cache_path.resolve())):
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise AttemptedToWriteOutsideCachedir(filepath)
        # Validate the contents of the cached file
        if filepath.is_file():
            # Validate the sha and write out
            sha = sha.upper()
            calculate = hashlib.sha256()
            async with GzipFile(filepath, "rb") as f:
                chunk = await f.read(chunk_size)
                while chunk:
                    calculate.update(chunk)
                    chunk = await f.read(chunk_size)
            # Validate the sha and exit if it is correct, otherwise update
            gotsha = calculate.hexdigest().upper()
            if gotsha != sha:
                filepath.unlink()
                self.LOGGER.debug(
                    f"SHA mismatch for {filename} (have: {gotsha}, want: {sha})"
                )
            else:
                self.LOGGER.debug(f"Correct SHA for {filename}")
                return
        self.LOGGER.debug(f"Updating CVE cache for {filename}")
        async with await session.get(url) as response:
            # Raise better error message on ratelimit by NVD
            if response.status == 403:
                with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                    raise NVDRateLimit(
                        f"{url} : download failed, you may have been rate limited."
                    )
            # Raise for all other 4xx errors
            response.raise_for_status()
            gzip_data = await response.read()
        json_data = gzip.decompress(gzip_data)
        gotsha = hashlib.sha256(json_data).hexdigest().upper()
        async with FileIO(filepath, "wb") as filepath_handle:
            await filepath_handle.write(gzip_data)
        # Raise error if there was an issue with the sha
        if gotsha != sha:
            # Remove the file if there was an issue
            # exit(100)
            filepath.unlink()
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise SHAMismatch(f"{url} (have: {gotsha}, want: {sha})")

    def load_nvd_year(self, year: int) -> dict[str, Any]:
        """
        Return the dict of CVE data for the given year.
        """

        filename = Path(self.cachedir) / self.NVDCVE_FILENAME_TEMPLATE.format(year)
        # Check if file exists
        if not filename.is_file():
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise CVEDataForYearNotInCache(year)
        # Open the file and load the JSON data, log the number of CVEs loaded
        with gzip.open(filename, "rb") as fileobj:
            cves_for_year = json.load(fileobj)
            self.LOGGER.debug(
                f'Year {year} has {len(cves_for_year["CVE_Items"])} CVEs in dataset'
            )
            return cves_for_year

    def nvd_years(self) -> list[int]:
        """
        Return the years we have NVD data for.
        """
        return sorted(
            int(filename.split(".")[-3].split("-")[-1])
            for filename in glob.glob(str(Path(self.cachedir) / "nvdcve-1.1-*.json.gz"))
        )

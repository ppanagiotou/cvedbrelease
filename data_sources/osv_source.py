# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import datetime
import io
import json
import zipfile
from pathlib import Path

import aiohttp
from cvss import CVSS3

from cve_bin_tool.async_utils import FileIO, aio_run_command
from data_sources import DISK_LOCATION_DEFAULT, Data_Source
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.log import LOGGER


class OSV_Source(Data_Source):

    SOURCE = "OSV"
    CACHEDIR = DISK_LOCATION_DEFAULT
    LOGGER = LOGGER.getChild("CVEDB")
    OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/"
    OSV_GS_URL = "gs://osv-vulnerabilities/"

    def __init__(
        self, error_mode: ErrorMode = ErrorMode.TruncTrace, incremental_update=False
    ):
        self.cachedir = self.CACHEDIR
        self.ecosystems = None
        self.osv_path = str(Path(self.cachedir) / "osv")
        self.source_name = self.SOURCE

        self.error_mode = error_mode
        self.incremental_update = incremental_update

        self.osv_url = self.OSV_URL
        self.gs_url = self.OSV_GS_URL
        self.all_cve_entries = []

    async def update_ecosystems(self):
        """Gets names of all ecosystems that OSV provides."""

        ecosystems = []

        stdout, _, _ = await aio_run_command(["gsutil", "ls", self.gs_url])
        stdout = str(stdout).split("gs")
        stdout.pop(0)

        for line in stdout:
            ecosystem = line.split("/")[-2]
            ecosystems.append(ecosystem)

        self.ecosystems = ecosystems

    async def get_ecosystem(self, ecosystem_url, mode="json"):
        """Fetches either a specific CVE or all.zip(containing all CVEs) file from an ecosystem."""

        async with aiohttp.ClientSession(trust_env=True) as session:
            async with session.get(ecosystem_url) as r:
                if mode == "bytes":
                    content = await r.read()
                else:
                    content = await r.json()
                return content

    async def get_ecosystem_incremental(self, ecosystem, time_of_last_update):
        """Fetches list of new CVEs and uses get_ecosystem to get them."""

        gs_file = self.gs_url + ecosystem
        stdout, _, _ = await aio_run_command(["gsutil", "ls", "-l", gs_file])
        stdout = str(stdout).split("json")

        newfiles = []

        for line in stdout:
            filename, timestamp = self.parse_filename(line)

            if timestamp is not None and timestamp > time_of_last_update:
                newfiles.append(filename)

        tasks = []

        for file in newfiles:
            eco_url = self.osv_url + ecosystem + "/" + file
            task = self.get_ecosystem(eco_url)
            tasks.append(task)

        for r in await asyncio.gather(*tasks):
            filepath = Path(self.osv_path) / (r.get("id") + ".json")
            r = json.dumps(r)

            async with FileIO(filepath, "w") as f:
                await f.write(r)

    def parse_filename(self, str):
        str = str.split("  ")

        filename = str[-1]

        if "zip" in filename:
            return None, None

        filename = filename.split("/")[-1] + "json"
        timestamp = datetime.datetime.strptime(str[-2], "%Y-%m-%dT%H:%M:%SZ")

        return filename, timestamp

    async def fetch_cves(self):
        """Fetches CVEs from OSV and places them in osv_path."""

        LOGGER.info("Getting OSV CVEs...")

        from cve_bin_tool import cvedb  # prevent cyclic import

        self.db = cvedb.CVEDB()

        if not Path(self.osv_path).exists():
            Path(self.osv_path).mkdir()

        if self.incremental_update and self.db.dbpath.exists():
            time_of_last_update = datetime.datetime.fromtimestamp(
                self.db.get_db_update_date()
            )
            for ecosystem in self.ecosystems:
                await self.get_ecosystem_incremental(ecosystem, time_of_last_update)
        else:
            tasks = []

            for ecosystem in self.ecosystems:
                eco_url = self.osv_url + ecosystem + "/all.zip"
                task = self.get_ecosystem(eco_url, mode="bytes")

                tasks.append(task)

            for r in await asyncio.gather(*tasks):

                z = zipfile.ZipFile(io.BytesIO(r))
                z.extractall(self.osv_path)

    async def update_cve_entries(self):
        """Updates CVE entries from CVEs in cache"""

        p = Path(self.osv_path).glob("**/*")
        files = [x for x in p if x.is_file()]
        self.all_cve_entries = []

        for file in files:
            async with FileIO(file, "r") as f:
                r = await f.read()
                data = json.loads(r)

                self.all_cve_entries.append(data)

    def format_data(self, all_cve_entries):
        severity_data = []
        affected_data = []

        for cve_item in all_cve_entries:
            cve_in_alias = None

            for cve in cve_item.get("aliases", []):
                if "CVE" in cve:
                    cve_in_alias = cve
                    break

            # if CVE has alias of the form "CVE-year-xxxx" keep that as CVE ID, will help in checking for duplicates
            cve_id = cve_in_alias if cve_in_alias is not None else cve_item["id"]
            severity = cve_item.get("severity", None)
            vector = None

            # getting score
            # OSV Schema currently only provides CVSS V3 scores, though more scores may be added in the future
            if severity is not None and "CVSS_V3" in [x["type"] for x in severity]:
                vector = severity[0]["score"]
                try:
                    vector = CVSS3(vector)
                    version = "3"
                    severity = vector.severities()[0]
                    score = vector.scores()[0]

                    vector = vector.clean_vector()

                except Exception as e:
                    LOGGER.debug(e)

                    vector = None

            publishedDate = datetime.datetime.fromisoformat(cve_item['published'].replace("Z", "+00:00"))

            cve = {
                "ID": cve_id,
                "severity": severity if vector is not None else "unknown",
                "description": cve_item.get("summary", None),
                "score": score if vector is not None else "unknown",
                "CVSS_version": version if vector is not None else "unknown",
                "CVSS_vector": vector if vector is not None else "unknown",
                "publishedDate": publishedDate if publishedDate is not None else "unknown",
            }

            severity_data.append(cve)

            for package in cve_item["affected"]:
                product = package["package"]["name"]
                vendor = (
                    "unknown"  # OSV Schema does not provide vendor names for packages
                )
                if "/" in product and "github":
                    vendor = product.split("/")[-2]  # trying to guess vendor name
                    product = product.split("/")[-1]

                affected = {
                    "cve_id": cve_id,
                    "vendor": vendor,
                    "product": product,
                    "version": "*",
                    "versionStartIncluding": "",
                    "versionStartExcluding": "",
                    "versionEndIncluding": "",
                    "versionEndExcluding": "",
                }

                events = None
                for ranges in package.get("ranges", []):
                    if ranges["type"] != "GIT":
                        events = ranges["events"]

                if events is None:
                    versions = package["versions"]

                    if versions == []:
                        continue

                    affected["versionStartIncluding"] = versions[0]
                    affected["versionEndIncluding"] = versions[-1]

                    affected_data.append(affected)
                else:
                    introduced = None
                    fixed = None

                    for event in events:
                        if event.get("introduced", None):
                            introduced = event.get("introduced")
                        if event.get("fixed", None):
                            fixed = event.get("fixed")

                        if fixed is not None:
                            affected["versionStartIncluding"] = introduced
                            affected["versionEndExcluding"] = fixed

                            fixed = None

                            affected_data.append(affected)

        return severity_data, affected_data

    async def get_cve_data(self):
        await self.update_ecosystems()
        await self.fetch_cves()
        await self.update_cve_entries()

        return self.format_data(self.all_cve_entries), self.source_name

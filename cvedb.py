"""
Retrieval access and caching of NIST CVE database
Getting only released date
Similarly and based on: https://github.com/intel/cve-bin-tool/blob/master/cve_bin_tool/cvedb.py
"""
import argparse
import os
import re
import datetime
import gzip
import json
import glob
import shutil
import sqlite3
import hashlib
import logging
import sys
import tempfile
import functools
import traceback
import contextlib
import multiprocessing
from dateutil import parser

try:
    import urllib.request as request
except:
    import urllib2 as request

# create formatter
formatter = logging.Formatter(fmt='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s',
                              datefmt='%Y-%m-%d %H:%M:%S')

name = "info"
level = logging.INFO
# initialise stream logger
logger = logging.getLogger()
logger.setLevel(level)
# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(level)
# add formatter to ch
ch.setFormatter(formatter)
# add ch to logger
logger.addHandler(ch)
LOGGER = logger

DISK_LOCATION_DEFAULT = os.path.join(os.path.expanduser("~"), ".cache", "cvedbrelease")
DBNAME = "cvedb.db"


class EmptyCache(Exception):
    """
    Raised when NVD is opened when verify=False and there are no files in the
    cache.
    """


class CVEDataForYearNotInCache(Exception):
    """
    Raised when the CVE data for a year is not present in the cache.
    """


class AttemptedToWriteOutsideCachedir(Exception):
    """
    Raised if we attempted to write to a file that would have been outside the
    cachedir.
    """


class SHAMismatch(Exception):
    """
    Raised if the sha of a file in the cache was not what it should be.
    """


def log_traceback(func, *args, **kwargs):
    """
    Multiprocessing won't print tracebacks, so log them
    """
    logger = logging.getLogger(__name__ + "." + func.__name__)
    try:
        return func(*args, logger=logger, **kwargs)
    except:
        logger.error(traceback.format_exc().strip())
        raise


def getmeta(metaurl, logger=LOGGER):
    with contextlib.closing(request.urlopen(metaurl)) as response:
        return (
            metaurl.replace(".meta", ".json.gz"),
            dict(
                [
                    line.split(":", 1)
                    for line in (response.read().decode()).split("\r\n")
                    if ":" in line
                ]
            ),
        )


def cache_update(cachedir, url, sha, chunk_size=16 * 1024, logger=LOGGER):
    """
    Update the cache for a single year of NVD data.
    """
    filename = url.split("/")[-1].replace(".gz", "")
    # Ensure we only write to files within the cachedir
    filepath = os.path.abspath(os.path.join(cachedir, filename))
    if not filepath.startswith(os.path.abspath(cachedir)):
        raise AttemptedToWriteOutsideCachedir(filepath)
    # Validate the contents of the cached file
    if os.path.isfile(filepath):
        # Validate the sha and write out
        sha = sha.upper()
        calculate = hashlib.sha256()
        with open(filepath, "rb") as handle:
            chunk = handle.read(chunk_size)
            while chunk:
                calculate.update(chunk)
                chunk = handle.read(chunk_size)
        # Validate the sha and exit if it is correct, otherwise update
        gotsha = calculate.hexdigest().upper()
        if gotsha != sha:
            os.unlink(filepath)
            logger.warning(f"SHA mismatch for {filename} (have: {gotsha}, want: {sha})")
        else:
            logger.debug(f"Correct SHA for {filename}")
            return
    logger.info(f"Updating CVE cache for {filename}")
    with tempfile.TemporaryFile(prefix="cvedb-") as temp_file:
        with contextlib.closing(request.urlopen(url)) as response:
            # Write to tempfile (gzip doesnt support reading from urlopen on
            # Python 2)
            shutil.copyfileobj(response, temp_file)
        # Replace the file with the tempfile
        temp_file.seek(0)
        with gzip.GzipFile(fileobj=temp_file, mode="rb") as jsondata_fileobj:
            # Validate the sha
            sha = sha.upper()
            calculate = hashlib.sha256()
            # Copy the contents while updating the sha
            with open(filepath, "wb") as filepath_handle:
                chunk = jsondata_fileobj.read(chunk_size)
                while chunk:
                    calculate.update(chunk)
                    filepath_handle.write(chunk)
                    chunk = jsondata_fileobj.read(chunk_size)
            # Raise error if there was an issue with the sha
            gotsha = calculate.hexdigest().upper()
            if gotsha != sha:
                # Remove the file if there was an issue
                os.unlink(filepath)
                raise SHAMismatch(f"{url} (have: {gotsha}, want: {sha})")


class CVEDB(object):
    """
    Downloads NVD data in json form and stores it on disk in a cache.
    """

    CACHEDIR = os.path.join(os.path.expanduser("~"), ".cache", "cvedbrelease")
    FEED = "https://nvd.nist.gov/vuln/data-feeds"
    NVDCVE_FILENAME_TEMPLATE = "nvdcve-1.1-{}.json"
    META_REGEX = re.compile(r"https:\/\/.*\/json\/.*-[0-9]*\.[0-9]*-[0-9]*\.meta")
    RANGE_UNSET = ""
    LOGGER = LOGGER

    def __init__(self, verify=True, feed=None, cachedir=None):
        self.verify = verify
        self.feed = feed if feed is not None else self.FEED
        self.cachedir = cachedir if cachedir is not None else self.CACHEDIR

        if not os.path.exists(self.cachedir):
            os.makedirs(self.cachedir, exist_ok=True)

        # Will be true if refresh was successful
        self.was_updated = False

        # set up the db if needed
        self.disk_location = DISK_LOCATION_DEFAULT
        self.dbname = os.path.join(self.disk_location, DBNAME)
        self.connection = None

    def nist_scrape(self, feed):
        with contextlib.closing(request.urlopen(feed)) as response:
            page = response.read().decode()
            jsonmetalinks = self.META_REGEX.findall(page)
            pool = multiprocessing.Pool()
            try:
                metadata = dict(
                    pool.map(
                        functools.partial(log_traceback, getmeta), tuple(jsonmetalinks)
                    )
                )
                pool.close()
                return metadata
            except:
                pool.terminate()
                raise
            finally:
                pool.join()

    def init_database(self):
        """ Initialize db tables used for storing cve/version data """
        conn = sqlite3.connect(self.dbname)
        db_cursor = conn.cursor()
        cve_data_create = """CREATE TABLE IF NOT EXISTS cve_released (
        cve_number TEXT,
        publish_date DATE,
        PRIMARY KEY(cve_number)
        )
        """
        db_cursor.execute(cve_data_create)

        conn.commit()
        return conn

    def open(self):
        """ Opens connection to sqlite database."""
        self.connection = sqlite3.connect(self.dbname, check_same_thread=False)

    def close(self):
        """ Closes connection to sqlite database."""
        self.connection.close()
        self.connection = None

    def __enter__(self):
        """ Opens connection to sqlite database."""
        self.open()

    def __exit__(self, exc_type, exc, exc_tb):
        """ Closes connection to sqlite database."""
        self.close()

    def get_cvelist_if_stale(self):
        """ Update if the local db is more than one day old.
        This avoids the full slow update with every execution.
        """
        if not os.path.isfile(self.dbname) or (
            datetime.datetime.today()
            - datetime.datetime.fromtimestamp(os.path.getmtime(self.dbname))
        ) > datetime.timedelta(hours=24):
            self.refresh_cache_and_update_db()
        else:
            self.LOGGER.info(
                "Using cached CVE data (<24h old). Use -u now to update immediately."
            )

    def refresh_cache_and_update_db(self):
        self.LOGGER.info("Updating CVE data. This will take a few minutes.")
        # refresh the nvd cache
        self.refresh()
        # if the database isn't open, open it
        if self.connection is None:
            self.connection = self.init_database()
        self.populate_db()

    def get_cves(self, lcve_number):

        if self.connection is None:
            self.open()

        cursor = self.connection.cursor()

        query = """SELECT cve_number, publish_date FROM cve_released WHERE cve_number = ?"""
        cvedict = dict()
        for cve_number in lcve_number:
            cursor.execute(query, [cve_number])
            for cve_res in cursor:
                (
                    cve_number,
                    publish_date,
                ) = cve_res
                cvedict[cve_res[0]] = cve_res[1]

        return cvedict

    def populate_db(self):
        """ Function that populates the database from the JSON.

        WARNING: After some inspection of the data, we are assuming that start/end ranges are kept together
        in single nodes.  This isn't *required* by the json so may not be true everywhere.  If that's the case,
        we'll need a better parser to match those together.
        """
        if self.connection is None:
            self.connection = self.open()

        cursor = self.connection.cursor()

        # Do only years with updates?
        for year in self.years():
            cve_data = self.year(year)
            self.LOGGER.debug(
                f'Time = {datetime.datetime.today().strftime("%H:%M:%S")}'
            )
            for cve_item in cve_data["CVE_Items"]:
                # the information we want:
                # CVE ID, Severity, Score ->
                # affected {Vendor(s), Product(s), Version(s)}
                CVE = dict()
                CVE["ID"] = cve_item["cve"]["CVE_data_meta"]["ID"]
                CVE["publishedDate"] = parser.isoparse(cve_item["publishedDate"])

                #CVE["publishedDate"] = datetime.datetime.fromisoformat(cve_item["publishedDate"])
                    #strptime("%Y-%m-%dT%H:%M", cve_item["publishedDate"])

                q = "INSERT or REPLACE INTO cve_released(CVE_number, publish_date) \
                VALUES (?, ?)"
                cursor.execute(
                    q, [CVE["ID"], CVE["publishedDate"]]
                )

            self.connection.commit()

    def refresh(self):
        if not os.path.isdir(self.cachedir):
            os.makedirs(self.cachedir)
        update = self.nist_scrape(self.feed)
        pool = multiprocessing.Pool()
        try:
            for result in [
                pool.apply_async(
                    functools.partial(log_traceback, cache_update),
                    (self.cachedir, url, meta["sha256"]),
                )
                for url, meta in update.items()
            ]:
                result.get()
            pool.close()
            self.was_updated = True
        except:
            pool.terminate()
            raise
        finally:
            pool.join()

    def year(self, year):
        """
        Return the dict of CVE data for the given year.
        """
        filename = os.path.join(
            self.cachedir, self.NVDCVE_FILENAME_TEMPLATE.format(year)
        )
        # Check if file exists
        if not os.path.isfile(filename):
            raise CVEDataForYearNotInCache(year)
        # Open the file and load the JSON data, log the number of CVEs loaded
        with open(filename, "rb") as fileobj:
            cves_for_year = json.load(fileobj)
            self.LOGGER.debug(
                f'Year {year} has {len(cves_for_year["CVE_Items"])} CVEs in dataset'
            )
            return cves_for_year

    def years(self):
        """
        Return the years we have NVD data for.
        """
        return sorted(
            [
                int(filename.split(".")[-2].split("-")[-1])
                for filename in glob.glob(
                    os.path.join(self.cachedir, "nvdcve-1.1-*.json")
                )
            ]
        )

    def __enter__(self):
        if not self.verify:
            self.LOGGER.error("Not verifying CVE DB cache")
            if not self.years():
                raise EmptyCache(self.cachedir)
        self.LOGGER.debug(f"Years present: {self.years()}")
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        pass

    def clear_cached_data(self):
        if os.path.exists(self.cachedir):
            self.LOGGER.warning(f"Deleting cachedir {self.cachedir}")
            shutil.rmtree(self.cachedir)


def refresh():
    with CVEDB():
        pass


def getOptions(args=None):
    if args is None:
        args = sys.argv[1:]
    parser = argparse.ArgumentParser(description="Parses command.")
    parser.add_argument("-u", "--update", help="Update CVE database.", dest='update', action="store_true", default=False)
    parser.add_argument("-s", "--search", help="Search for a CVE. Example: -s CVE-2018-0539 -s CVE-2018-0541", dest='cve_number', action='append')
    options = parser.parse_args(args)
    return options

if __name__ == "__main__":

    # parse arguments
    options = getOptions()

    cvedb = CVEDB()

    if options.update:
        cvedb.init_database()
        cvedb.clear_cached_data()
        cvedb.refresh_cache_and_update_db()

    if options.cve_number != None:
        resdict = cvedb.get_cves(options.cve_number)
        print(json.dumps(resdict))
    else:
        print("{}")

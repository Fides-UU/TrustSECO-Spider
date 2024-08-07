"""File containing the CVE spider.

This file contains the logic for crawling through the [CVE website](https://cve.mitre.org/index.html).

This crawling is done by using the [Requests](https://requests.readthedocs.io/en/latest/) library for HTTP calls,
and the [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/bs4/doc/) library for HTML parsing.
"""

import logging
import requests


class CVESpider:
    """Class containing the CVE spider."""

    def get_cve_vulnerability_count(self, name: str) -> int | None:
        """Function to get the amount of vulnerabilities affecting the given
        package.

        Args:
            name (str): The name of the package.

        Returns:
            int | None: The amount of known vulnerabilities of the given
            package. None if api returns error.
        """

        if cve_data := self.request_cve_data(name):
            return cve_data["totalResults"]
        else:
            return None

    def get_all_cve_data(self, name: str) -> list | None:
        """Function to get all CVE data for a given package.

        Args:
            name (str): The name of the package.

        Returns:
            list: A list of all the CVE data for the given package.
        """

        # TODO: this only uses the first 40 vurlnerabilities otherwise the
        # result gets to big which in turn can't be stored on the dlt.
        # It would probably be better to fix this in the dlt/cosy side
        if cve_data := self.request_cve_data(name):
            return [
                self.extract_cve_data(vulnerabilitie)
                for vulnerabilitie in cve_data["vulnerabilities"]
            ][:40]
        else:
            return None

    def get_cve_codes(self, name: str) -> list | None:
        """Function for getting all CVE codes that affect a given package.

        Args:
            name (str): The name of the package.

        Returns:
            list: A list of CVE codes affecting the given package.
        """

        if cve_data := self.request_cve_data(name):
            return [
                vulnerabilitie["cve"]["id"]
                for vulnerabilitie in cve_data["vulnerabilities"]
            ]
        else:
            return None

    def extract_cve_data(self, data: dict) -> dict:
        """Function to extract the needed data from the api json.

        The data it can extract contains:
            - CVE code
            - CVE score
            - Affected versions:
                - Start version type
                - Start version
                - End version type
                - End version

        Args:
            data (dict): The raw CVE data.

        Returns:
            dict: A dictionary containing the extracted data.
        """

        affected_version_start = None
        affected_version_start_type = None
        affected_version_end = None
        affected_version_end_type = None
        configurations = data["cve"].get("configurations")

        if configurations is not None:
            cpe_match = configurations[0]["nodes"][0]["cpeMatch"][0]

            if affected_version_start := cpe_match.get("versionStartIncluding"):
                affected_version_start_type = "including"
            elif affected_version_start := cpe_match.get("versionStartExcluding"):
                affected_version_start_type = "excluding"

            if affected_version_end := cpe_match.get("versionEndIncluding"):
                affected_version_end_type = "including"
            elif affected_version_end := cpe_match.get("versionEndExcluding"):
                affected_version_end_type = "excluding"
        else:
            logging.info(f'{data["cve"]["id"]}: Could not find affected versions.')

        score = None

        try:
            metric_version = list(data["cve"]["metrics"].keys())[0]
            score = data["cve"]["metrics"][metric_version][0]["cvssData"]["baseScore"]
        except IndexError:
            logging.info(f'{data["cve"]["id"]}: Could not find score.')

        cve_data = {
            "CVE_ID": data["cve"]["id"],
            "CVE_score": score,
            "CVE_affected_version_start_type": affected_version_start_type,
            "CVE_affected_version_start": affected_version_start,
            "CVE_affected_version_end_type": affected_version_end_type,
            "CVE_affected_version_end": affected_version_end,
        }

        return cve_data

    def request_cve_data(self, package_name: str) -> dict | None:
        """Get all cves for a corresponding package.

        For more information read the api documentation:
        https://nvd.nist.gov/developers/vulnerabilities

        Args:
            package_name: Name of the package to search for.

        Returns:
            Json response of the api, None if the request was not sucessful
        """
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:*:*:{package_name}"
        resp = requests.get(url)
        if resp.status_code == 200:
            return resp.json()
        else:
            return None


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

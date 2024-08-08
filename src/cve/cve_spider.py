"""File containing the CVE spider.

This file contains the logic for the cve API.

For more info on the API visit the documentation:
https://nvd.nist.gov/developers/vulnerabilities
"""

import logging
import requests
from packaging.version import Version, InvalidVersion


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
                self.extract_cve_data(vulnerabilitie, name)
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

    def extract_cve_data(self, data: dict, package_name: str) -> dict:
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
            package_name (str): The name of the package we are extracting the
                data for.

        Returns:
            dict: A dictionary containing the extracted data.
        """

        affected_versions_dict = self.extract_affected_versions(data, package_name)

        score = None

        try:
            metric_version = list(data["cve"]["metrics"].keys())[0]
            score = data["cve"]["metrics"][metric_version][0]["cvssData"]["baseScore"]
        except IndexError:
            logging.info(f'{data["cve"]["id"]}: Could not find score.')

        cve_data = {
            "CVE_ID": data["cve"]["id"],
            "CVE_score": score,
            "CVE_affected_version_start_type": affected_versions_dict[
                "CVE_affected_version_start_type"
            ],
            "CVE_affected_version_start": affected_versions_dict[
                "CVE_affected_version_start"
            ],
            "CVE_affected_version_end_type": affected_versions_dict[
                "CVE_affected_version_end_type"
            ],
            "CVE_affected_version_end": affected_versions_dict[
                "CVE_affected_version_end"
            ],
        }

        return cve_data

    def extract_affected_versions(self, data: dict, package_name: str) -> dict:
        """Function to extract the affected version data.

        Args:
            data (dict): The raw CVE data.
            package_name (str): The name of the package we are extracting the
                affected versions for.

        Returns:
            dict: A dictionary containing the extracted data.
        """
        affected_version_start = None
        affected_version_start_type = None
        affected_version_end = None
        affected_version_end_type = None
        configurations = data["cve"].get("configurations")

        if configurations is not None:
            # first get all the cpeMatch data, this is contained in nodes which
            # are contained in configurations
            cpe_matches = [
                cpe
                for configuration in configurations
                for node in configuration["nodes"]
                for cpe in node["cpeMatch"]
            ]

            # next filter out all non matching criteria, this is needed because
            # os versions which contain the broken packages are also included
            cpe_matches_filtered = list(
                filter(
                    lambda cpe_match: cpe_match["criteria"].split(":")[4]
                    == package_name,
                    cpe_matches,
                )
            )

            # next sort them by version for each key and grab the lowest one
            versions_start_incl = self.sort_by_version(
                cpe_matches_filtered, "versionStartIncluding"
            )
            versions_start_excl = self.sort_by_version(
                cpe_matches_filtered, "versionStartExcluding"
            )
            if len(versions_start_excl) > 0 and (
                len(versions_start_incl) <= 0
                or versions_start_excl < versions_start_incl
            ):
                affected_version_start_type = "excluding"
                affected_version_start = str(versions_start_excl[0])
            elif len(versions_start_incl) > 0:
                affected_version_start_type = "including"
                affected_version_start = str(versions_start_incl[0])

            # grab the highest for the upper version limit
            versions_end_incl = self.sort_by_version(
                cpe_matches_filtered, "versionEndIncluding"
            )
            versions_end_excl = self.sort_by_version(
                cpe_matches_filtered, "versionEndExcluding"
            )
            if len(versions_end_excl) > 0 and (
                len(versions_end_incl) <= 0 or versions_end_excl > versions_end_incl
            ):
                affected_version_end_type = "excluding"
                affected_version_end = str(versions_end_excl[-1])
            elif len(versions_end_incl) > 0:
                affected_version_end_type = "including"
                affected_version_end = str(versions_end_incl[-1])
        else:
            logging.info(f'{data["cve"]["id"]}: Could not find affected versions.')

        return {
            "CVE_affected_version_start_type": affected_version_start_type,
            "CVE_affected_version_start": affected_version_start,
            "CVE_affected_version_end_type": affected_version_end_type,
            "CVE_affected_version_end": affected_version_end,
        }

    def sort_by_version(self, cpe_matches: list[dict], key: str) -> list[Version]:
        """Gathers all the versions stored unders a specific key.

        Args:
            cpe_matches (list[dict]): A list of cpeMatch dicts to search
                through.
            key (str): The key where the versions should be gathered from in
                the cpeMatch dicts, versionEndExcluding for example.

        Returns:
            list[Version]: A sorted list of all versions.
        """
        versions = []
        for cpe_match in cpe_matches:
            try:
                versions.append(Version(cpe_match[key]))
            except InvalidVersion:
                pass
            except KeyError:
                pass
        return sorted(versions)

    def request_cve_data(self, package_name: str) -> dict | None:
        """Get all cves for a corresponding package.

        Args:
            package_name: Name of the package to search for.

        Returns:
            Json response of the api, None if the request was not sucessful
        """
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:*:{package_name}"
        resp = requests.get(url)
        if resp.status_code == 200:
            return resp.json()
        else:
            return None


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

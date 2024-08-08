"""File containing the unit tests for the cve_spider.py file."""

# Unit testing imports
import pytest
from unittest import mock

# Import for sending and handling HTTP requests
import responses

# Import for parsing and searching through HTML
from bs4 import BeautifulSoup

# Import for setting parameter types
from typing import List

# CVE spider imports
from src.cve.cve_spider import CVESpider
from tests.unit_tests.spider_tests.file_io import FileIOForCVETests


class TestVulnerabilityCount:
    """Class containing the tests for the get_cve_vulnerability_count function."""

    @pytest.mark.parametrize(
        "return_value, expected_value",
        [
            (None, None),
            (FileIOForCVETests.get_zero_cves(), 0),
            (FileIOForCVETests.get_express_cves(), 5),
        ],
    )
    def test_all(self, return_value: List[str], expected_value: int) -> None:
        """Test for all of the possible scenarios, using mocking to change the output of the get_cve_codes function.

        Args:
            return_value (List[str]): The value that the request_cve_data function will return.
            expected_value (int): The expected value that the get_cve_codes function will return.
        """
        # Initialise the CVESpider object
        cve_spider = CVESpider()

        with mock.patch(
            "src.cve.cve_spider.CVESpider._CVESpider__request_cve_data", return_value=return_value
        ):
            # Call the get_cve_vulnerability_count function
            result = cve_spider.get_cve_vulnerability_count("test_package")

            # Check the result
            assert result == expected_value


class TestGetAllCVEData:
    """Class containing all the tests for the get_all_cve_data function."""

    @pytest.mark.parametrize(
        "api_response,expected_value",
        [
            (FileIOForCVETests.get_zero_cves(), []),
            (None, None),
            (
                FileIOForCVETests.get_numpy_cves(),
                [
                    {
                        "CVE_ID": "CVE-2021-33430",
                        "CVE_score": 5.3,
                        "CVE_affected_version_start_type": "including",
                        "CVE_affected_version_start": "1.9.0",
                        "CVE_affected_version_end_type": "including",
                        "CVE_affected_version_end": "1.9.3",
                    },
                    {
                        "CVE_ID": "CVE-2021-34141",
                        "CVE_score": 5.3,
                        "CVE_affected_version_start_type": "including",
                        "CVE_affected_version_start": "1.17.0",
                        "CVE_affected_version_end_type": "excluding",
                        "CVE_affected_version_end": "1.23.0",
                    },
                ],
            ),
        ],
    )
    def test_get_all(self, api_response, expected_value) -> None:
        cve_spider = CVESpider()

        with mock.patch(
            "src.cve.cve_spider.CVESpider._CVESpider__request_cve_data", return_value=api_response
        ):
            assert cve_spider.get_all_cve_data("numpy") == expected_value


class TestGetCVECodes:
    """Class containing all the tests for the get_cve_codes function."""

    @pytest.mark.parametrize(
        "api_response,expected_value",
        [
            (None, None),
            (FileIOForCVETests.get_zero_cves(), []),
            (
                FileIOForCVETests.get_express_cves(),
                [
                    "CVE-2005-3673",
                    "CVE-2014-6887",
                    "CVE-2014-6393",
                    "CVE-2022-27152",
                    "CVE-2022-24999",
                ],
            ),
        ],
    )
    def test_get_cve_codes(self, api_response, expected_value):
        cve_spider = CVESpider()

        with mock.patch(
            "src.cve.cve_spider.CVESpider._CVESpider__request_cve_data", return_value=api_response
        ):
            assert cve_spider.get_cve_codes("test_package") == expected_value


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

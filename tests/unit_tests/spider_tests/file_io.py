"""File containing all the IO logic for the spider unit tests"""

import json


class FileIOForGHSpiderTests:
    """Class containing all of the IO functions for the spider tests."""

    # Test users
    def get_regular_body_users() -> str:
        """Gets the regular page for the GitHub users tests.

        Returns:
            str: The regular page for the GitHub users tests.
        """

        with open('tests/unit_tests/spider_tests/spider_files/gh_user_count/regular.txt', 'r', encoding='iso-8859-15') as regular:
            return regular.read()

    def get_no_tag_body_users() -> str:
        """Gets the no-tag page for the GitHub users tests.

        Returns:
            str: The no-tag page for the GitHub users tests.
        """

        with open('tests/unit_tests/spider_tests/spider_files/gh_user_count/no_a_tag.txt', 'r', encoding='iso-8859-15') as no_tag:
            return no_tag.read()

    def get_no_title_body_users() -> str:
        """Gets the no-title page for the GitHub users tests.

        Returns:
            str: The no-title page for the GitHub users tests.
        """

        with open('tests/unit_tests/spider_tests/spider_files/gh_user_count/no_title_attribute.txt', 'r', encoding='iso-8859-15') as no_title:
            return no_title.read()

    # Test issues
    def get_regular_body_issues() -> str:
        """Gets the regular page for the GitHub issues tests.

        Returns:
            str: The regular page for the GitHub issues tests.
        """

        with open('tests/unit_tests/spider_tests/spider_files/gh_issue_ratio/regular.txt', 'r', encoding='iso-8859-15') as regular:
            return regular.read()

    def get_no_open_body_issues() -> str:
        """Gets the no-open issues page for the GitHub issues tests.

        Returns:
            str: The no-open issues page for the GitHub issues tests.
        """

        with open('tests/unit_tests/spider_tests/spider_files/gh_issue_ratio/no_open_issues.txt', 'r', encoding='iso-8859-15') as no_open:
            return no_open.read()

    def get_zero_open_body_issues() -> str:
        """Gets the zero-open issues page for the GitHub issues tests.

        Returns:
            str: The zero-open issues page for the GitHub issues tests.
        """

        with open('tests/unit_tests/spider_tests/spider_files/gh_issue_ratio/zero_open_issues.txt', 'r', encoding='iso-8859-15') as zero_open:
            return zero_open.read()

    def get_no_closed_body_issues() -> str:
        """Gets the no-closed issues page for the GitHub issues tests.

        Returns:
            str: The no-closed issues page for the GitHub issues tests.
        """

        with open('tests/unit_tests/spider_tests/spider_files/gh_issue_ratio/no_closed_issues.txt', 'r', encoding='iso-8859-15') as no_closed:
            return no_closed.read()

    def get_zero_closed_body_issues() -> str:
        """Gets the zero-closed issues page for the GitHub issues tests.

        Returns:
            str: The zero-closed issues page for the GitHub issues tests.
        """

        with open('tests/unit_tests/spider_tests/spider_files/gh_issue_ratio/zero_closed_issues.txt', 'r', encoding='iso-8859-15') as zero_closed:
            return zero_closed.read()


class FileIOForCVETests:
    """Class containing all of the IO functions for the CVE tests."""

    def get_zero_cves() -> dict:
        """Get api response with zero cves."""

        with open('tests/unit_tests/spider_tests/spider_files/cve_api/0_cves.json', 'r') as zero_cves:
            return json.loads(zero_cves.read())

    def get_express_cves() -> dict:
        """Get api response for express package. Contains 5 cves."""

        with open('tests/unit_tests/spider_tests/spider_files/cve_api/express_5_cves.json', 'r') as express_cves:
            return json.loads(express_cves.read())

    def get_numpy_cves() -> dict:
        """Get api response for express package. Contains 5 cves."""

        with open('tests/unit_tests/spider_tests/spider_files/cve_api/numpy_cves.json', 'r') as numpy_cves:
            return json.loads(numpy_cves.read())


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

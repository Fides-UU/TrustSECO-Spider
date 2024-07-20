"""File containing all the IO logic for the spider unit tests"""


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

    def get_regular_page_extract() -> str:
        """Gets the regular page for the CVE extract tests.

        Returns:
            str: The html page
        """

        with open('tests/unit_tests/spider_tests/spider_files/cve_extract/regular_vulnerability_page.txt', 'r', encoding='iso-8859-15') as regular:
            return regular.read()

    def get_no_version_page_extract() -> str:
        """Gets the page with no version data for the CVE extract tests.

        Returns:
            str: The html page
        """

        with open('tests/unit_tests/spider_tests/spider_files/cve_extract/no_version_vulnerability_page.txt', 'r', encoding='iso-8859-15') as no_version:
            return no_version.read()

    def get_no_score_page_extract() -> str:
        """Gets the page with no score data for the CVE extract tests.

        Returns:
            str: The html page
        """
        with open('tests/unit_tests/spider_tests/spider_files/cve_extract/no_score_vulnerability_page.txt', 'r', encoding='iso-8859-15') as no_score:
            return no_score.read()

    def get_incorrect_version_page_extract() -> str:
        """Gets the page with incorrect version data for the CVE extract tests.

        Returns:
            str: The html page
        """

        with open('tests/unit_tests/spider_tests/spider_files/cve_extract/incorrect_version_vulnerability_page.txt', 'r', encoding='iso-8859-15') as incorrect_version:
            return incorrect_version.read()

    def get_regular_page_get_codes() -> str:
        """Gets the regular page for the CVE get_codes tests.

        Returns:
            str: The html page
        """

        with open('tests/unit_tests/spider_tests/spider_files/cve_get_codes/regular_page.txt', 'r', encoding='iso-8859-15') as regular:
            return regular.read()

    def get_no_tables_page_get_codes() -> str:
        """Gets the page with no tables for the CVE get_codes tests.

        Returns:
            str: The html page
        """

        with open('tests/unit_tests/spider_tests/spider_files/cve_get_codes/no_tables_page.txt', 'r', encoding='iso-8859-15') as no_tables:
            return no_tables.read()

    def get_no_links_page_get_codes() -> str:
        """Gets the page with no links for the CVE get_codes tests.

        Returns:
            str: The html page
        """

        with open('tests/unit_tests/spider_tests/spider_files/cve_get_codes/no_links_page.txt', 'r', encoding='iso-8859-15') as no_links:
            return no_links.read()

    def get_missing_table_page_get_codes() -> str:
        """Gets the page with a missing table for the CVE get_codes tests.

        Returns:
            str: The html page
        """

        with open('tests/unit_tests/spider_tests/spider_files/cve_get_codes/missing_table_page.txt', 'r', encoding='iso-8859-15') as missing_table:
            return missing_table.read()


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

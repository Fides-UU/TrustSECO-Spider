"""
File containing the unit tests for the github_spider.py file.
"""

# Unit testing imports
from unittest import mock
# Import for sending and handling HTTP requests
import responses
# GitHub spider imports
from src.github.github_spider import GitHubSpider
# FileIO import
from tests.unit_tests.spider_tests.file_io import FileIOForGHSpiderTests

# Spider object initialization
spider = GitHubSpider()


class TestUserCount:
    """Class containing the tests for the get_repository_user_count function.

    We will test the following scenario's:
    1. The get request failed:
        - The response code is not 200.
        - The response body is empty.
    2. The get request succeeded but the number of users is not found:
        - The response body is empty.
        - The 'used by' <a> tag is not found.
        - The 'used by' <a> tag has no 'title' attribute.
    3. The get request succeeded and the number of users is found.
    """

    owner = 'numpy'
    repo = 'numpy'
    url = f'https://github.com/{owner}/{repo}'

    @ responses.activate
    def test_invalid_response_code(self) -> None:
        """Test for when the request returns an invalid response.

        i.e. a response with a code other than 200.
        """

        # Get the mock response body
        regular_body = FileIOForGHSpiderTests.get_regular_body_users()

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body=regular_body, status=404)

        # Get the result
        result = spider.get_repository_user_count(self.owner, self.repo)

        # The result should be None as the get request failed
        assert result is None

    @ responses.activate
    def test_empty_response_body(self) -> None:
        """Test for when the request body is empty."""

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body='', status=200)

        # Get the result
        result = spider.get_repository_user_count(self.owner, self.repo)

        # The result should be None as the response had no body, hence no user count could be found
        assert result is None

    @ responses.activate
    def test_user_count_tag_not_found(self) -> None:
        """Test for when the request body is not empty but the 'used by' <a> tag can not be found."""

        # Get the mock response body
        no_tag_body = FileIOForGHSpiderTests.get_no_tag_body_users()

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body=no_tag_body, status=200)

        # Get the result
        result = spider.get_repository_user_count(self.owner, self.repo)

        # The result should be None as the 'used by' <a> tag was not found
        assert result is None

    @ responses.activate
    def test_no_title_attribute(self) -> None:
        """Test for when the request body is not empty, and the 'used by' <a> tag is found, but the tag does not have a 'title' attribute."""

        # Get the mock response body
        no_title_body = FileIOForGHSpiderTests.get_no_title_body_users()

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body=no_title_body, status=200)

        # Get the result
        result = spider.get_repository_user_count(self.owner, self.repo)

        # The result should be None as the 'used by' <a> tag had no 'title' attribute
        assert result is None

    @ responses.activate
    def test_user_count_found(self) -> None:
        """Test for when the request body is not empty, and the 'used by' <a> tag is found, and the tag has a 'title' attribute."""

        # Get the mock response body
        regular_body = FileIOForGHSpiderTests.get_regular_body_users()

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body=regular_body, status=200)

        # Get the result
        result = spider.get_repository_user_count(self.owner, self.repo)

        # The result should be the number of users
        assert result == 975170


class TestOpenIssues:
    """Class containing the tests for the get_repository_open_issue_count function.

    We will test the following scenario's:
    1. The get request failed:
        - The response code is not 200.
        - The response body is empty.
    2. The get request succeeded but the open issue count is not found.
    3. The get request succeeded and the open issue count is found.
    """

    owner = 'numpy'
    repo = 'numpy'
    url = f'https://github.com/{owner}/{repo}/issues'

    @ responses.activate
    def test_invalid_response_code(self) -> None:
        """Test for when the request returns an invalid response.

        i.e. a response with a code other than 200.
        """

        # Get the mock response body
        regular_body = FileIOForGHSpiderTests.get_regular_body_issues()

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body=regular_body, status=404)

        # Get the result
        result = spider.get_repository_open_issue_count(self.owner, self.repo)

        # The result should be None as the get request failed
        assert result is None

    @ responses.activate
    def test_empty_response_body(self) -> None:
        """Test for when the request body is empty."""

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body='', status=200)

        # Get the result
        result = spider.get_repository_open_issue_count(self.owner, self.repo)

        # The result should be None as the response had no body, hence no issue count could be found
        assert result is None

    @ responses.activate
    def test_no_open_issues(self) -> None:
        """Test for when the request body is not empty, but the open issue count can not be found."""

        # Get the mock response body
        no_open_body = FileIOForGHSpiderTests.get_no_open_body_issues()

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body=no_open_body, status=200)

        # Get the result
        result = spider.get_repository_open_issue_count(self.owner, self.repo)

        # The result should be None as the open issue count was not found
        assert result is None

    @responses.activate
    def test_open_issue_count_found(self) -> None:
        """Test for when the request body is not empty, and the open issue count is found."""

        # Get the mock response body
        regular_body = FileIOForGHSpiderTests.get_regular_body_issues()

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body=regular_body, status=200)

        # Get the result
        result = spider.get_repository_open_issue_count(self.owner, self.repo)

        # The result should be the open issue count
        assert result == 2026


class TestClosedIssues:
    """Class containing the tests for the get_repository_closed_issue_count function.

    We will test the following scenario's:
    1. The get request failed:
        - The response code is not 200.
        - The response body is empty.
    2. The get request succeeded but the closed issue count is not found.
    3. The get request succeeded and the closed issue count is found.
    """

    owner = 'numpy'
    repo = 'numpy'
    url = f'https://github.com/{owner}/{repo}/issues'

    @ responses.activate
    def test_invalid_response_code(self) -> None:
        """Test for when the request returns an invalid response.

        i.e. a response with a code other than 200.
        """

        # Get the mock response body
        regular_body = FileIOForGHSpiderTests.get_regular_body_issues()

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body=regular_body, status=404)

        # Get the result
        result = spider.get_repository_closed_issue_count(
            self.owner, self.repo)

        # The result should be None as the get request failed
        assert result is None

    @ responses.activate
    def test_empty_response_body(self) -> None:
        """Test for when the request body is empty."""

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body='', status=200)

        # Get the result
        result = spider.get_repository_closed_issue_count(
            self.owner, self.repo)

        # The result should be None as the response had no body, hence no issue count could be found
        assert result is None

    @ responses.activate
    def test_no_closed_issues(self) -> None:
        """Test for when the request body is not empty, but the closed issue count can not be found."""

        # Get the mock response body
        no_closed_body = FileIOForGHSpiderTests.get_no_closed_body_issues()

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body=no_closed_body, status=200)

        # Get the result
        result = spider.get_repository_closed_issue_count(
            self.owner, self.repo)

        # The result should be None as the closed issue count was not found
        assert result is None

    @responses.activate
    def test_closed_issue_count_found(self) -> None:
        """Test for when the request body is not empty, and the closed issue count is found."""

        # Get the mock response body
        regular_body = FileIOForGHSpiderTests.get_regular_body_issues()

        # Tell responses to mock the request for us using the provided body and code
        responses.add(responses.GET, self.url, body=regular_body, status=200)

        # Get the result
        result = spider.get_repository_closed_issue_count(
            self.owner, self.repo)

        # The result should be the closed issue count
        assert result == 8387


class TestIssueRatio:
    """Class containing the tests for the get_repository_issue_ratio function.

    We will test the following scenario's:
    1. Both open and closed issue counts are valid numbers.
    2. The open issue count is None.
    3. The closed issue count is None.
    4. Both open and closed issue counts are None.
    """

    owner = 'numpy'
    repo = 'numpy'
    url = f'https://github.com/{owner}/{repo}/issues'

    @mock.patch('src.github.github_spider.GitHubSpider.get_repository_open_issue_count', new=mock.Mock(return_value=2026))
    @mock.patch('src.github.github_spider.GitHubSpider.get_repository_closed_issue_count', new=mock.Mock(return_value=8387))
    def test_both_successful(self) -> None:
        """Test for when both the open and closed issue counts are valid numbers."""

        result = spider.get_repository_issue_ratio(self.owner, self.repo)

        # The result should be the issue ratio
        assert result == 0.24156432574222012

    @mock.patch('src.github.github_spider.GitHubSpider.get_repository_open_issue_count', new=mock.Mock(return_value=2026))
    @mock.patch('src.github.github_spider.GitHubSpider.get_repository_closed_issue_count', new=mock.Mock(return_value=None))
    def test_open_successful_close_failed(self) -> None:
        """Test for when the closed issue count is not a valid number."""

        result = spider.get_repository_issue_ratio(self.owner, self.repo)

        assert result is None

    @mock.patch('src.github.github_spider.GitHubSpider.get_repository_open_issue_count', new=mock.Mock(return_value=None))
    @mock.patch('src.github.github_spider.GitHubSpider.get_repository_closed_issue_count', new=mock.Mock(return_value=8387))
    def test_open_failed_closed_successful(self) -> None:
        """Test for when the closed issue count is not a valid number."""

        result = spider.get_repository_issue_ratio(self.owner, self.repo)

        assert result is None

    @mock.patch('src.github.github_spider.GitHubSpider.get_repository_open_issue_count', new=mock.Mock(return_value=None))
    @mock.patch('src.github.github_spider.GitHubSpider.get_repository_closed_issue_count', new=mock.Mock(return_value=None))
    def test_both_failed(self) -> None:
        """Test for when both the open and closed issue counts are not valid numbers."""

        result = spider.get_repository_issue_ratio(self.owner, self.repo)

        assert result is None


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

"""File containing the unit tests for the controller module."""

# Imports for testing
import pytest
from unittest import mock
# Import the Controller class
from controller import Controller


class TestControllerRun:
    """Class containing the unit tests for the controller module."""

    def test_run_no_proj_info(self) -> None:
        """Test for when the project information is missing from the input JSON."""
        # make an input JSON with no project information
        input_json = {}

        # Run the controller with the input JSON
        result = Controller().run(input_json)

        # Check that the response is correct
        assert result == {'Error': 'Error: no project information found'}

    @pytest.mark.parametrize('input_json, return_value', [
        (
            {"project_info": {
                "project_owner": 'numpy',
                "project_name": 'numpy',
                "project_release": 'v1.22.1'}},
            {'Error': 'missing project information (project_platform)'}
        ),
        (
            {"project_info": {
                "project_platform": 'Pypi',
                "project_name": 'numpy',
                "project_release": 'v1.22.1'}},
            {'Error': 'missing project information (project_owner)'}
        ),
        (
            {"project_info": {
                "project_platform": 'Pypi',
                "project_owner": 'numpy',
                "project_release": 'v1.22.1'}},
            {'Error': 'missing project information (project_name)'}
        ),
        (
            {"project_info": {
                "project_platform": 'Pypi',
                "project_owner": 'numpy',
                "project_name": 'numpy'}},
            {'Error': 'missing project information (project_release)'}
        )
    ])
    def test_run_missing_info(self, input_json: dict, return_value: dict) -> None:
        """Test for when a required field within the project information is missing from the input JSON.

        Args:
            input_json (dict): The input json to run the controller with
            return_value (dict): The expected return value
        """

        # Run the controller with the input JSON
        response_data = Controller().run(input_json)

        # Assert that the returned error is equal to the defined error in the controller
        assert response_data == return_value

    @mock.patch('controller.Controller.get_github_data', new=mock.Mock(return_value={"gh": "mock"}))
    def test_run_gh(self) -> None:
        """ Test for when we only request GitHub data from the Controller."""

        # make an input JSON with only requesting GitHub data
        input_json = {
            "project_info": {
                "project_platform": "Pypi",
                "project_owner": "numpy",
                "project_name": "numpy",
                "project_release": "v1.22.1"
            },
            "gh_data_points": [],
        }

        # Run the controller with the input JSON
        result = Controller().run(input_json)

        # Assert that the return value is equal to the mock value
        # as this indicates that the get_github_data was successfully called
        assert result == {"gh": "mock"}

    @mock.patch('controller.Controller.get_libraries_data', new=mock.Mock(return_value={"lb": "mock"}))
    def test_run_lib(self) -> None:
        """Test for when we only request Libraries.io data from the Controller."""

        # make an input JSON with only requesting Libraries.io data
        input_json = {
            "project_info": {
                "project_platform": "Pypi",
                "project_owner": "numpy",
                "project_name": "numpy",
                "project_release": "v1.22.1"
            },
            "lib_data_points": [],
        }

        # Run the controller with the input JSON
        result = Controller().run(input_json)

        # Assert that the return value is equal to the mock value
        # as this indicates that the get_libraries_data was successfully called
        assert result == {"lb": "mock"}

    @mock.patch('controller.Controller.get_cve_data', new=mock.Mock(return_value={"cve": "mock"}))
    def test_run_cve(self) -> None:
        """Test for when we only request CVE data from the Controller."""

        # make an input JSON with only requesting CVE data
        input_json = {
            "project_info": {
                "project_platform": "Pypi",
                "project_owner": "numpy",
                "project_name": "numpy",
                "project_release": "v1.22.1"
            },
            "cve_data_points": [],
        }

        # Run the controller with the input JSON
        result = Controller().run(input_json)

        # Assert that the return value is equal to the mock value
        # as this indicates that the get_cve_data was successfully called
        assert result == {"cve": "mock"}

    @mock.patch('controller.Controller.get_so_data', new=mock.Mock(return_value={"so": "mock"}))
    def test_run_so(self) -> None:
        """Test for when we only request Stack Overflow data from the Controller."""

        # make an input JSON with only requesting Stack Overflow data
        input_json = {
            "project_info": {
                "project_platform": "Pypi",
                "project_owner": "numpy",
                "project_name": "numpy",
                "project_release": "v1.22.1",
            },
            "so_data_points": [],
        }

        # Run the controller with the input JSON
        result = Controller().run(input_json)

        # Assert that the return value is equal to the mock value
        # as this indicates that the get_so_data was successfully called
        assert result == {"so": "mock"}

    @mock.patch('controller.Controller.get_virus_data', new=mock.Mock(return_value={"virus": "mock"}))
    def test_run_virus(self) -> None:
        """Test for when we only request virus scan data from the Controller."""

        # make an input JSON with only requesting virus scan data
        input_json = {
            "project_info": {
                "project_platform": "Pypi",
                "project_owner": "numpy",
                "project_name": "numpy",
                "project_release": "v1.22.1"
            },
            "virus_scanning": [],
        }

        # Run the controller with the input JSON
        result = Controller().run(input_json)

        # Assert that the return value is equal to the mock value
        # as this indicates that the get_virus_data was successfully called
        assert result == {"virus": "mock"}


class TestControllerData:

    # Mock all of the GitHub API functions
    @mock.patch('src.github.github_api_calls.GitHubAPICall.get_average_issue_resolution_time', new=mock.Mock(return_value=300))
    @mock.patch('src.github.github_api_calls.GitHubAPICall.get_gitstar_ranking', new=mock.Mock(return_value=4))
    @mock.patch('src.github.github_api_calls.GitHubAPICall.get_issue_count_per_release', new=mock.Mock(return_value=5))
    @mock.patch('src.github.github_api_calls.GitHubAPICall.get_owner_stargazer_count', new=mock.Mock(return_value=2))
    @mock.patch('src.github.github_api_calls.GitHubAPICall.get_release_download_count', new=mock.Mock(return_value=11))
    @mock.patch('src.github.github_api_calls.GitHubAPICall.get_repository_contributor_count', new=mock.Mock(return_value=3))
    @mock.patch('src.github.github_api_calls.GitHubAPICall.get_repository_language', new=mock.Mock(return_value="Python"))
    @mock.patch('src.github.github_api_calls.GitHubAPICall.get_total_download_count', new=mock.Mock(return_value=23))
    @mock.patch('src.github.github_api_calls.GitHubAPICall.get_yearly_commit_count', new=mock.Mock(return_value=50))
    @mock.patch('src.github.github_api_calls.GitHubAPICall.get_zero_responses_issue_count', new=mock.Mock(return_value=2))
    # Mock all of the GitHub spider functions
    @mock.patch('src.github.github_spider.GitHubSpider.get_repository_issue_ratio', new=mock.Mock(return_value=0.6))
    @mock.patch('src.github.github_spider.GitHubSpider.get_repository_open_issue_count', new=mock.Mock(return_value=3))
    @mock.patch('src.github.github_spider.GitHubSpider.get_repository_user_count', new=mock.Mock(return_value=20))
    def test_get_github_data(self) -> None:
        """Test for making sure that the GitHub data-requests are made correctly."""

        # Set the required inputs
        owner = "numpy"
        repo_name = "numpy"
        release = "v1.22.1"
        # Set the wanted data to all of the GitHub data points
        wanted_data = [
            "gh_average_resolution_time",
            "gh_gitstar_ranking",
            "gh_release_issues_count",
            "gh_owner_stargazer_count",
            "gh_release_download_count",
            "gh_contributor_count",
            "gh_repository_language",
            "gh_total_download_count",
            "gh_yearly_commit_count",
            "gh_zero_response_issues_count",
            "gh_issue_ratio",
            "gh_open_issues_count",
            "gh_user_count",
            "unknown"
        ]

        # Run the controller with the input JSON
        result = Controller().get_github_data(owner, repo_name, release, wanted_data)

        # Assert that the returned dictionary only contains the Github data
        # and that the value is equal to the one we specified
        assert result == {
            "gh_average_resolution_time": 300,
            "gh_gitstar_ranking": 4,
            "gh_release_issues_count": 5,
            "gh_owner_stargazer_count": 2,
            "gh_release_download_count": 11,
            "gh_contributor_count": 3,
            "gh_repository_language": "Python",
            "gh_total_download_count": 23,
            "gh_yearly_commit_count": 50,
            "gh_zero_response_issues_count": 2,
            "gh_issue_ratio": 0.6,
            "gh_open_issues_count": 3,
            "gh_user_count": 20,
            "unknown": None,
        }

    # Mock all of the Libraries.io API functions
    @mock.patch('src.libraries_io.libraries_io_api_calls.LibrariesAPICall.get_contributors_count', new=mock.Mock(return_value=5))
    @mock.patch('src.libraries_io.libraries_io_api_calls.LibrariesAPICall.get_dependency_count', new=mock.Mock(return_value=3))
    @mock.patch('src.libraries_io.libraries_io_api_calls.LibrariesAPICall.get_dependent_count', new=mock.Mock(return_value=2))
    @mock.patch('src.libraries_io.libraries_io_api_calls.LibrariesAPICall.get_first_release_date', new=mock.Mock(return_value='2016-04-19T04:09:15.000Z'))
    @mock.patch('src.libraries_io.libraries_io_api_calls.LibrariesAPICall.get_latest_release_date', new=mock.Mock(return_value='2016-04-20T04:09:15.000Z'))
    @mock.patch('src.libraries_io.libraries_io_api_calls.LibrariesAPICall.get_release_count', new=mock.Mock(return_value=2))
    @mock.patch('src.libraries_io.libraries_io_api_calls.LibrariesAPICall.get_release_frequency', new=mock.Mock(return_value=1))
    @mock.patch('src.libraries_io.libraries_io_api_calls.LibrariesAPICall.get_sourcerank', new=mock.Mock(return_value=5))
    def test_get_libraries_data(self) -> None:
        """Test for making sure that the Libraries.io data-requests are made correctly."""

        # Set the required inputs
        platform = "Pypi"
        owner = "numpy"
        repo_name = "numpy"
        release = "v1.22.1"
        # Set the wanted data to all of the Libraries.io data points
        wanted_data = [
            "lib_contributor_count",
            "lib_dependency_count",
            "lib_dependent_count",
            "lib_first_release_date",
            "lib_latest_release_date",
            "lib_release_count",
            "lib_release_frequency",
            "lib_sourcerank",
            "unknown"
        ]

        # Run the function we are testing
        result = Controller().get_libraries_data(
            platform, owner, repo_name, release, wanted_data)

        # Assert that the returned dictionary only contains the Libraries.io data
        # and that the value is equal to the one we specified
        assert result == {
            "lib_contributor_count": 5,
            "lib_dependency_count": 3,
            "lib_dependent_count": 2,
            "lib_first_release_date": "2016-04-19T04:09:15.000Z",
            "lib_latest_release_date": "2016-04-20T04:09:15.000Z",
            "lib_release_count": 2,
            "lib_release_frequency": 1,
            "lib_sourcerank": 5,
            "unknown": None,
        }

    # Mock all of the CVE spider functions
    @mock.patch('src.cve.cve_spider.CVESpider.get_cve_codes', new=mock.Mock(return_value=[1, 2, 3]))
    @mock.patch('src.cve.cve_spider.CVESpider.get_all_cve_data', new=mock.Mock(return_value=[1, 2, 3, 4]))
    @mock.patch('src.cve.cve_spider.CVESpider.get_cve_vulnerability_count', new=mock.Mock(return_value=1))
    def test_get_cve_data(self) -> None:
        """Test for making sure that the CVE data-requests are made correctly."""

        # Set the required inputs
        repo_name = 'numpy'
        # Set the wanted data to all of the CVE data points
        wanted_data = [
            'cve_codes',
            'cve_count',
            'cve_vulnerabilities',
            'unknown'
        ]

        # Run the function we are testing
        result = Controller().get_cve_data(repo_name, wanted_data)

        # Assert that the returned dictionary contains the CVE data
        # and that the value is equal to the one we specified
        assert result == {
            "cve_codes": [1, 2, 3],
            "cve_count": 1,
            "cve_vulnerabilities": [1, 2, 3, 4],
            "unknown": None,
        }

    # Mock all of the Stack Overflow spider functions
    @mock.patch('src.stackoverflow.stackoverflow_api_calls.StackOverflowAPICall.get_monthly_popularity', new=mock.Mock(return_value={"month": 0, "year": 1, "popularity": 2}))
    def test_get_so_data(self) -> None:
        """Test for making sure that the Stack Overflow data-requests are made correctly."""

        # Set the required inputs
        repo_name = 'numpy'
        # Set the wanted data to all of the Stack Overflow data points
        wanted_data = [
            'so_popularity',
            'unknown'
        ]

        # run the controller with the input JSON
        result = Controller().get_so_data(repo_name, wanted_data)

        # Assert that the returned dictionary only contains the Stack Overflow data
        # and that the value is equal to the one we specified
        assert result == {
            'so_popularity': {
                "month": 0,
                "year": 1,
                "popularity": 2
            },
            'unknown': None,
        }

    # Mock all of the virus scan functions
    @mock.patch('src.clamav.clamav_scanner.ClamAVScanner.get_virus_ratio', new=mock.Mock(return_value=0.0))
    @mock.patch('src.github.github_api_calls.GitHubAPICall.get_release_download_links', new=mock.Mock(return_value=['']))
    def test_get_virus_data(self) -> None:
        """Test for making sure that the virus data-requests are made correctly."""

        # Set the required inputs
        owner = 'numpy'
        repo_name = 'numpy'
        release = 'v1.22.1'
        # Set the wanted data to all of the virus scan data points
        wanted_data = [
            'vs_virus_ratio',
            'unknown'
        ]

        # Run the controller with the input JSON
        result = Controller().get_virus_data(owner, repo_name, release, wanted_data)

        # Assert that the returned dictionary only contains the virus ratio
        # and that the value of that ratio is equal to the one we specified
        assert result == {
            'vs_virus_ratio': 0.0,
            'unknown': None,
        }


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

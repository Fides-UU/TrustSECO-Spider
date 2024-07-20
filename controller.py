"""File containing the Controller of the TrustSECO-Spider

The Controller class contains the logic used to run the spider.
This entails parsing the JSON input, delegating the work to the
various sub-modules, and returning the result as an HTTP response.

It also contains some static methods that the Flask app uses to
communicate with the controller.
"""

# Imports for environmental variables
import os
from dotenv import set_key, load_dotenv
# Import for improved logging
import logging

# Import the data-getting modules
# API calls
from src.github.github_api_calls import GitHubAPICall
from src.libraries_io.libraries_io_api_calls import LibrariesAPICall
from src.stackoverflow.stackoverflow_api_calls import StackOverflowAPICall
# Spiders
from src.github.github_spider import GitHubSpider
from src.cve.cve_spider import CVESpider
# Virus scanning
from src.clamav.clamav_scanner import ClamAVScanner

# Imports for utilities
import src.utils.constants as constants
# Import for setting parameter types
from typing import List


class Controller:
    """Class methods for controlling the TrustSECO-Spider

    The only outside-used method is the `run` method. This method
    receives an JSON object as input, and will return an JSON object as output.
    The output JSON object will contain the data as requested by the input JSON object.

    Attributes:
        gh_api (GitHubAPICall): The GitHub API object.
        lib_api (LibrariesAPICall): The Libraries.IO API object.
        gh_spider (GitHubSpider): The GitHub spider object.
        cve_spider (CVESpider): The CVE spider object.
        so_spider (StackOverflowSpider): The StackOverflow spider object.
    """

    def __init__(self) -> None:
        """Initializes the Controller object by setting the data-gathering objects."""
        # API objects
        self.gh_api = GitHubAPICall()
        self.lib_api = LibrariesAPICall()

        # Spider objects
        self.gh_spider = GitHubSpider()
        self.cve_spider = CVESpider()
        self.so_spider = StackOverflowAPICall()

        # Virus scanner objects
        self.vs_comm = ClamAVScanner()

    def run(self, input_json: dict) -> dict:
        """Allows data-requests to be made to the controller

        This is the main function of the TrustSECO-Spider. It receives
        a JSON object as input, and will return a JSON object as output.
        This output JSON object will contain the data as requested by the input JSON object.
        This data is gathered by delegating the work to the various sub-modules.

        Args:
            input_json (dict): The input JSON object. 
                This input JSON object contains information about which package is to be spidered, and what data is to be returned.

        Returns:
            dict: The output JSON object. This output JSON object contains the data as requested by the input JSON object.
        """

        # Make sure we got the information we need
        if 'project_info' not in input_json:
            logging.error('No project information found')
            return {'Error': 'Error: no project information found'}

        # Make sure all of the wanted project information is available
        if 'project_platform' not in input_json['project_info']:
            logging.error('Missing project information (project_platform)')
            return {'Error': 'missing project information (project_platform)'}

        if 'project_owner' not in input_json['project_info']:
            logging.error('Missing project information (project_owner)')
            return {'Error': 'missing project information (project_owner)'}

        if 'project_name' not in input_json['project_info']:
            logging.error('Missing project information (project_name)')
            return {'Error': 'missing project information (project_name)'}

        if 'project_release' not in input_json['project_info']:
            logging.error('Missing project information (project_release)')
            return {'Error': 'missing project information (project_release)'}

        # Retrieve the project information
        platform = input_json['project_info']['project_platform']
        owner = input_json['project_info']['project_owner']
        repo_name = input_json['project_info']['project_name']
        release = input_json['project_info']['project_release']

        # Create an output JSON object
        output_json = {}

        # Request the data from GitHub
        if 'gh_data_points' in input_json:
            # Tell the user what is going on
            logging.info('-------------------')
            logging.info('Getting GitHub data...')

            # Actually request the data
            output_json.update(self.get_github_data(
                owner, repo_name, release, input_json["gh_data_points"]))

        # Request the data from Libraries.IO
        if 'lib_data_points' in input_json:
            # Tell the user what is going on
            logging.info('-------------------')
            logging.info('Getting Libraries.IO data...')

            # Libraries.io does not use 'v' in their version numbers, so we need to remove it if it is there
            if release[0].lower() == 'v':
                lib_release = release[1:]
            else:
                lib_release = release

            # Actually request the data
            output_json.update(self.get_libraries_data(
                platform, owner, repo_name, lib_release, input_json["lib_data_points"]))

        # Request the data from the CVE website
        if 'cve_data_points' in input_json:
            # Tell the user what is going on
            logging.info('-------------------')
            logging.info('Getting CVE data...')

            # Actually request the data
            output_json.update(self.get_cve_data(
                repo_name, input_json["cve_data_points"]))

        # Request the data from the StackOverflow website
        if 'so_data_points' in input_json:
            # Tell the user what is going on
            logging.info('-------------------')
            logging.info('Getting StackOverflow data...')

            # Actually request the data
            output_json.update(self.get_so_data(
                repo_name, input_json["so_data_points"]))

        # Scan the release's files for viruses
        if 'virus_scanning' in input_json:
            # Tell the user what is going on
            logging.info('-------------------')
            logging.info('Scanning for viruses...')

            # Actually request the data
            output_json.update(self.get_virus_data(
                owner, repo_name, release, input_json["virus_scanning"]))

        logging.info('-------------------')

        # Return the found data
        return output_json

    def get_github_data(self, owner: str, repo_name: str, release: str, wanted_data: List[str]) -> dict:
        """Calls on the GitHub spider and API caller to get the data requested.

        Loops through the given `wanted_data` list, and sends the appropriate
        data-requests to the GitHub spider and API caller.

        Args:
            owner (str): The owner of the repository.
            repo_name (str): The name of the repository.
            release (str): The release name.
            wanted_data (List[str]): The list of data points to be returned.

        Returns:
            dict: The requested GitHub data
        """

        # Create a JSON object to store the data
        return_data = {}

        # Loop through the wanted data list and retrieve the data
        for data_point in wanted_data:
            # Initialise the value variable
            value = None

            if data_point == "gh_average_resolution_time":
                value = self.gh_api.get_average_issue_resolution_time(
                    owner, repo_name
                )
            elif data_point == "gh_contributor_count":
                value = self.gh_api.get_repository_contributor_count(
                    owner, repo_name
                )
            elif data_point == "gh_gitstar_ranking":
                value = self.gh_api.get_gitstar_ranking(
                    owner, repo_name
                )
            elif data_point == "gh_issue_ratio":
                value = self.gh_spider.get_repository_issue_ratio(
                    owner, repo_name
                )
            elif data_point == "gh_open_issues_count":
                value = self.gh_spider.get_repository_open_issue_count(
                    owner, repo_name
                )
            elif data_point == "gh_owner_stargazer_count":
                value = self.gh_api.get_owner_stargazer_count(
                    owner
                )
            elif data_point == "gh_release_download_count":
                value = self.gh_api.get_release_download_count(
                    owner, repo_name, release
                )
            elif data_point == "gh_release_issues_count":
                value = self.gh_api.get_issue_count_per_release(
                    owner, repo_name, release
                )
            elif data_point == "gh_repository_language":
                value = self.gh_api.get_repository_language(
                    owner, repo_name
                )
            elif data_point == "gh_total_download_count":
                value = self.gh_api.get_total_download_count(
                    owner, repo_name
                )
            elif data_point == "gh_user_count":
                value = self.gh_spider.get_repository_user_count(
                    owner, repo_name
                )
            elif data_point == "gh_yearly_commit_count":
                value = self.gh_api.get_yearly_commit_count(
                    owner, repo_name
                )
            elif data_point == "gh_zero_response_issues_count":
                value = self.gh_api.get_zero_responses_issue_count(
                    owner, repo_name
                )
            else:
                logging.warning(f"GitHub: Invalid data point {data_point}")

            # Update the dictionary
            return_data.update({data_point: value})

        # Return the requested data-points
        return return_data

    def get_libraries_data(self, platform: str, owner: str, repo_name: str, release: str, wanted_data: List[str]) -> dict:
        """Calls on the Libraries.io API caller to get the data requested.

        Loops through the given `wanted_data` list, and sends the appropriate
        data-requests to the Libraries.io API caller.

        Args:
            platform (str): The platform of the repository
            owner (str): The owner of the repository
            repo_name (str): The name of the repository
            release (str): The release name
            wanted_data (List[str]): The list of data points to be returned

        Returns:
            dict: The requested Libraries.IO data
        """

        # Create a JSON object to store the data
        return_data = {}

        # Loop through the wanted data list and retrieve the data
        for data_point in wanted_data:
            # Initialise the value variable
            value = None

            if data_point == "lib_contributor_count":
                value = self.lib_api.get_contributors_count(
                    owner, repo_name
                )
            elif data_point == "lib_dependency_count":
                value = self.lib_api.get_dependency_count(
                    platform, repo_name, release
                )
            elif data_point == "lib_dependent_count":
                value = self.lib_api.get_dependent_count(
                    platform, repo_name
                )
            elif data_point == "lib_first_release_date":
                value = self.lib_api.get_first_release_date(
                    platform, repo_name
                )
            elif data_point == "lib_latest_release_date":
                value = self.lib_api.get_latest_release_date(
                    platform, repo_name
                )
            elif data_point == "lib_release_count":
                value = self.lib_api.get_release_count(
                    platform, repo_name
                )
            elif data_point == "lib_release_frequency":
                value = self.lib_api.get_release_frequency(
                    platform, repo_name
                )
            elif data_point == "lib_sourcerank":
                value = self.lib_api.get_sourcerank(
                    platform, repo_name
                )
            else:
                logging.warning(
                    f"Libraries.io: Invalid data point {data_point}"
                )

            # Update the dictionary
            return_data.update({data_point: value})

        # Return the requested data-points
        return return_data

    def get_cve_data(self, repo_name: str, wanted_data: List[str]) -> dict:
        """Calls on the CVE spider to get the data requested.

        Loops through the given `wanted_data` list, and sends the appropriate
        data-requests to the CVE spider.

        Args:
            repo_name (str): The name of the repository
            wanted_data (List[str]): The list of data points to be returned

        Returns:
            dict: The requested CVE data
        """

        # Create a JSON object to store the data
        return_data = {}

        for data_point in wanted_data:
            # Initialise the value variable
            value = None

            if data_point == "cve_codes":
                value = self.cve_spider.get_cve_codes(
                    repo_name
                )
            elif data_point == "cve_count":
                value = self.cve_spider.get_cve_vulnerability_count(
                    repo_name
                )
            elif data_point == "cve_vulnerabilities":
                value = self.cve_spider.get_all_cve_data(
                    repo_name
                )
            else:
                logging.warning(f"CVE: Invalid data point {data_point}")

            # Update the dictionary
            return_data.update({data_point: value})

        # Return the requested data-points
        return return_data

    def get_so_data(self, repo_name: str, wanted_data: List[str]) -> dict:
        """Calls on the Stack Overflow spider to get the data requested.

        Loops through the given `wanted_data` list, and sends the appropriate
        data-requests to the Stack Overflow spider.

        Args:
            repo_name (str): The name of the repository
            wanted_data (List[str]): The list of data points to be returned

        Returns:
            dict: The requested Stack Overflow data
        """

        # Create a JSON object to store the data
        return_data = {}

        # Loop through all the wanted data points
        for data_point in wanted_data:
            # Initialise the value variable
            value = None

            if data_point == "so_popularity":
                value = self.so_spider.get_monthly_popularity(
                    repo_name
                )
            else:
                logging.warning(
                    f"StackOverflow: Invalid data point {data_point}"
                )

            # Update the dictionary
            return_data.update({data_point: value})

        # Return the requested data-points
        return return_data

    def get_virus_data(self, owner: str, repo_name: str, release: str, wanted_data: List[str]) -> dict:
        """Calls on the ClamAV virus scanning container to get the data requested.

        Loops through the given `wanted_data` list, and sends the appropriate
        data-requests to the ClamAV container.

        Requires the TrustSECO-Spider to be running in Docker, alongside
        the ClamAV container. The TrustSECO-Spider and the ClamAV container 
        should be run at the same time using the docker-compose.yml file.

        Args:
            owner (str): The owner of the repository
            repo_name (str): The name of the repository
            release (str): The release name
            wanted_data (List[str]): The list of data points to be returned

        Returns:
            dict: The requested virus data
        """

        # Create a JSON object to store the data
        return_data = {}

        # Get the download links for the files that we need to scan
        download_links = self.gh_api.get_release_download_links(
            owner, repo_name, release
        )

        # Loop through all the wanted data points
        for data_point in wanted_data:
            # Initialise the value variable
            value = None

            if data_point == 'vs_virus_ratio':
                value = self.vs_comm.get_virus_ratio(
                    download_links
                )
            else:
                logging.warning(
                    f"Virus scanning: Invalid data point {data_point}"
                )

            # Update the dictionary
            return_data.update({data_point: value})

        # Return the requested data-points
        return return_data


def get_data(input_json: dict) -> dict:
    """Function to activate the Controller, and pass on the wanted data-points.

    Args:
        input_json (dict): The received JSON input

    Returns:
        dict: The requested data
    """

    # Create a new controller
    controller = Controller()

    # Start the controller
    return controller.run(input_json)


def update_token_gh(github_token: str) -> None:
    """Updates the .env file with the given GitHub token.

    Args:
        github_token (str): The user's GitHub token
    """

    # Make sure the .env file exists
    if not os.path.exists(constants.ENVIRON_FILE):
        with open(constants.ENVIRON_FILE, 'w') as f:
            f.write(f'{constants.GITHUB_TOKEN}=\n{constants.LIBRARIES_TOKEN}=')

    # Update the .env file
    set_key(constants.ENVIRON_FILE, constants.GITHUB_TOKEN, github_token)


def update_token_lib(libraries_token: str) -> None:
    """Updates the .env file with the given Libraries.io token.

    Args:
        libraries_token (str): The user's Libraries.io token
    """

    # Make sure the .env file exists
    if not os.path.exists(constants.ENVIRON_FILE):
        with open(constants.ENVIRON_FILE, 'w') as f:
            f.write(f'{constants.GITHUB_TOKEN}=\n{constants.LIBRARIES_TOKEN}=')

    # Update the .env file
    set_key(constants.ENVIRON_FILE, constants.LIBRARIES_TOKEN, libraries_token)


def get_tokens() -> dict:
    """Returns the GitHub and Libraries.io tokens from the .env file.

    Returns:
        dict: The current GitHub and Libraries.io tokens
    """

    # (Re)load the .env file
    load_dotenv(dotenv_path=constants.ENVIRON_FILE, override=True)

    # Get the tokens
    gh_token = os.getenv(constants.GITHUB_TOKEN)
    lib_token = os.getenv(constants.LIBRARIES_TOKEN)

    # Return the keys
    return {
        'github_token': gh_token,
        'libraries_token': lib_token
    }


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

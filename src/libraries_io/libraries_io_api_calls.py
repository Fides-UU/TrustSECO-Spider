"""File for processing GitHub data-point requests.

This file contains all of the logic for processing Libraries.io data-point requests.
In order to do this, it contains a few functions that return most of the wanted data-points:
`LibrariesAPICall.get_project_repository`, `LibrariesAPICall.get_project_dependencies` and 
`LibrariesAPICall.get_project_information`.
"""

# Import for improved logging
import logging
# Import for handling dates
from datetime import datetime as dt
# Imports for utilities
import src.utils.constants as constants
from src.utils.api_calls import make_api_call


class LibrariesAPICall:
    """Class methods for getting data from Libraries.io

    This class contains all of the logic for getting data from Libraries.io.
    API calls are made to the Libraries.io API and the data is returned.
    If needed, it performs calculations to get the data.
    """

    def get_release_frequency(self, platform: str, name: str) -> int:
        """Function to get the average time per release.

        This is done using `LibrariesAPICall.get_release_count` function.
        This function also uses the `LibrariesAPICall.get_latest_release_date` 
        and `LibrariesAPICall.get_first_release_date` functions.

        Args:
            platform (str): The platform of the project.
            name (str): The name of the project.

        Returns:
            int: The average time per release.
        """

        logging.info('Getting the average release frequency')

        # Get the first and last release dates, so we know for how long the project has been active
        latest_release_date = self.get_latest_release_date(platform, name)
        first_release_date = self.get_first_release_date(platform, name)
        # Get the release count
        release_count = self.get_release_count(platform, name)

        # Make sure that none of the required values are None
        # As we wouldn't be able to calculate the release frequency otherwise
        if latest_release_date is not None and first_release_date is not None and release_count is not None:
            latest = dt.strptime(
                latest_release_date[:-5], '%Y-%m-%dT%H:%M:%S')
            first = dt.strptime(
                first_release_date[:-5], '%Y-%m-%dT%H:%M:%S')
            # Return the average time between releases
            return (latest - first).total_seconds() / release_count
        # Else, return None
        else:
            logging.error(
                'Error occurred while getting the average release frequency')
            return None

    def get_contributors_count(self, owner: str, name: str) -> int:
        """Function to get the project repository's contributor count.

        This is done using the `LibrariesAPICall.get_project_repository` function.

        Args:
            owner (str): The owner of the project.
            name (str): The name of the project.

        Returns:
            int: The project's repository contributor count.
        """

        logging.info('Getting the repository contributor count')

        # Get the repository data of this project
        data = self.get_project_repository(owner, name)

        # If we got a valid response, return the contributor count
        if data is not None and 'github_contributions_count' in data:
            return data['github_contributions_count']
        # Else, return None
        else:
            logging.error(
                "Error occurred while getting the project's repository contributor count")
            return None

    def get_dependency_count(self, platform: str, name: str, release: str) -> int:
        """Function to get the project's dependency count.

        This is done using the `LibrariesAPICall.get_project_dependencies` function.

        Args:
            platform (str): The platform of the project.
            name (str): The name of the project.
            release (str): The release name.

        Returns:
            int: The project's dependency count.
        """

        logging.info('Getting the dependency count')

        # Get the dependency data of this project
        data = self.get_project_dependencies(platform, name, release)

        # If we got a valid response, get the dependency count
        if data is not None and 'dependencies' in data:
            # Filter out the development dependencies, as they are not relevant for the final product
            count = 0
            for release in data['dependencies']:
                if 'kind' in release and release['kind'] != 'Development':
                    count += 1

            # Return the amount of dependencies
            return count
        # Else, return None
        else:
            logging.error(
                'Error occurred while getting the project dependency count')
            return None

    def get_dependent_count(self, platform: str, name: str) -> int:
        """Function to get the amount of dependents the project has.

        This is done using the `LibrariesAPICall.get_project_information` function.

        Args:
            platform (str): The platform of the project.
            name (str): The name of the project.

        Returns:
            int: The amount of dependents the project has.
        """

        logging.info('Getting the dependent count')

        # Get the project data
        data = self.get_project_information(platform, name)

        # If we got a valid response, return the dependent count
        if data is not None and 'dependents_count' in data:
            return data['dependents_count']
        # Else, return None
        else:
            logging.error(
                "Error occurred while getting the project's dependent count")
            return None

    def get_latest_release_date(self, platform: str, name: str) -> str:
        """Function to get the time of the project's latest release.

        This is done using the `LibrariesAPICall.get_project_information` function.

        Args:
            platform (str): The platform of the project.
            name (str): The name of the project.

        Returns:
            str: The time of the project's latest release (in the format YYYY-MM-DDTHH:MM:SS, using the UTC timezone).
        """

        logging.info('Getting the latest release date')

        # Get the project data
        data = self.get_project_information(platform, name)

        # If we got a valid response, return the latest release date
        if data is not None and 'latest_release_published_at' in data:
            return data['latest_release_published_at']
        # Else, return None
        else:
            logging.error(
                "Error occurred while getting the project's latest release date")
            return None

    def get_first_release_date(self, platform: str, name: str) -> str:
        """Function to get the time of the project's latest release.

        This is done using the `LibrariesAPICall.get_project_information` function.

        Args:
            platform (str): The platform of the project.
            name (str): The name of the project.

        Returns:
            str: The time of the project's latest release (in the format YYYY-MM-DDTHH:MM:SS, using the UTC timezone).
        """

        logging.info('Getting the first release date')

        # Get the project data
        data = self.get_project_information(platform, name)

        # If we got a valid response, return the first release date
        if data is not None and 'versions' in data:
            # Search through all the given releases
            # To find the first one, and return its date string
            current_earliest = dt.now()
            earliest_string = ''
            for version in data['versions']:
                # Get the publish date of the current version
                version_date = dt.strptime(
                    version['published_at'][:-5], '%Y-%m-%dT%H:%M:%S')
                # See if it is earlier than the current earliest
                if current_earliest > version_date:
                    # If so, update the local variables to reflect this
                    current_earliest = version_date
                    earliest_string = version['published_at']

            if earliest_string != '':
                # Return the string representation of the earliest date
                return earliest_string

        # Return None if we could not find the first release date
        logging.error(
            "Error occurred while getting the project's first release date")
        return None

    def get_release_count(self, platform: str, name: str) -> int:
        """Function to get the amount of releases the project has.

        This is done using the `LibrariesAPICall.get_project_information` function.

        Args:
            platform (str): The platform of the project.
            name (str): The name of the project.

        Returns:
            int: The amount of releases the project has.
        """

        logging.info('Getting the release count')

        # Get the project data
        data = self.get_project_information(platform, name)

        # If we got a valid response, return the release count
        if data is not None and 'versions' in data:
            return len(data['versions'])
        # Else, return None
        else:
            logging.error(
                "Error occurred while getting the project's release count")
            return None

    def get_sourcerank(self, platform: str, name: str) -> int:
        """Function to get the project's source rank.

        This is done using the `LibrariesAPICall.get_project_information` function.

        Args:
            platform (str): The platform of the project.
            name (str): The name of the project.

        Returns:
            int: The project's source rank.
        """

        logging.info('Getting the project source rank')

        # Get the project data
        data = self.get_project_information(platform, name)

        # If we got a valid response, return the source rank
        if data is not None and 'rank' in data:
            return data['rank']
        # Else, return None
        else:
            logging.error(
                "Error occurred while getting the project's source rank")
            return None

    def get_project_repository(self, owner: str, name: str) -> dict:
        """Function to get the project's repository information from Libraries.io.

        This is done by using the [Libraries.io repository API](https://libraries.io/api#repository).

        Args:
            owner (str): The owner of the project.
            name (str): The name of the project.

        Returns:
            dict: The project repository's information.
        """

        logging.info("Getting the project's repository information")

        # Setup the url, and perform the request
        repo_url = f'https://libraries.io/api/github/{owner}/{name}'
        data_response = make_api_call(repo_url, constants.API_LIBRARIES)

        # If the data_response is valid, return the json data
        if data_response is not None:
            return data_response.json()
        # Else, inform the user that the request has failed, and return None
        else:
            logging.error(
                "Error occurred while getting the project's repository information")
            return None

    def get_project_dependencies(self, platform: str, name: str, release: str) -> dict:
        """Function to get the project's dependencies from Libraries.io.

        This is done using the [Libraries.io project dependencies API](https://libraries.io/api#project-dependencies).

        Args:
            platform (str): The platform of the project.
            name (str): The name of the project.
            release (str): The release name.

        Returns:
            dict: The project's dependencies.
        """

        logging.info("Getting the project's dependency information")

        # Setup the url, and perform the request
        dependency_url = f'https://libraries.io/api/{platform}/{name}/{release}/dependencies'
        data_response = make_api_call(dependency_url, constants.API_LIBRARIES)

        # If the data_response is valid, return the json data
        if data_response is not None:
            return data_response.json()
        # Else, inform the user that the request has failed, and return None
        else:
            logging.error(
                "Error occurred while getting the project's dependency information")
            return None

    def get_project_information(self, platform: str, name: str) -> dict:
        """Function to get the project information from Libraries.io.

        This is done using the [Libraries.io project API](https://libraries.io/api#project).

        Args:
            platform (str): The platform of the project.
            name (str): The name of the project.

        Returns:
            dict: The project's information.
        """

        logging.info("Getting the project's information")

        # Setup the url, and perform the request
        repo_url = f'https://libraries.io/api/{platform}/{name}'
        data_response = make_api_call(repo_url, constants.API_LIBRARIES)

        # If the data_response is valid, return the json data
        if data_response is not None:
            return data_response.json()
        # Else, inform the user that the request has failed, and return None
        else:
            logging.error(
                "Error occurred while getting the project information")
            return None


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

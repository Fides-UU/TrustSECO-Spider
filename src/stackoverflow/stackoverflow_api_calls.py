"""File containing the Stack Overflow API call processor.

This file contains the logic for crawling through the [Stack Overflow website](https://stackoverflow.com/).

This API calls are done by using the [Requests](https://requests.readthedocs.io/en/latest/) library.
"""

# Import for improved logging
import logging
# Import for sending and handling HTTP requests
import requests


class StackOverflowAPICall:
    """Class methods for getting data from Stack Overflow"""

    def get_monthly_popularity(self, package: str) -> float:
        """Function to get the monthly popularity of a package.

        The data required is retrieved from the [Stack Overflow Insights API endpoint](https://insights.stackoverflow.com/trends/get-data)

        Args:
            package (str): The name of the package.

        Returns:
            float: The latest monthly popularity of the given package. This popularity is the percentage of questions posted that were about the given package.
        """

        logging.info('Getting monthly popularity')

        # Take the url for Stack Overflow trends
        url = 'https://insights.stackoverflow.com/trends/get-data'

        # Extract the data as json
        try:
            response = requests.get(url).json()
        except requests.exceptions.RequestException as e:
            logging.error(e)
            return None

        # Make sure we got the correct data
        if 'TagPercents' not in response:
            logging.error('Could not find TagPercents in response')
            return None

        # Make sure we got the correct data
        if response['TagPercents'] is None:
            logging.error('TagPercents is None')
            return None

        # Make sure that the package is in the response
        if package not in response['TagPercents']:
            logging.warning('Package not found in response')
            return 0

        # Return the latest monthly popularity of the given package
        return response['TagPercents'][package][-1]


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

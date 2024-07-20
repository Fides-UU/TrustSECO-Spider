"""File containing all of the logic pertaining to making actual API calls

This file handles all of the logic for actually making API calls.
This allows the program to be more modular and easier to maintain.

In order to send the HTTP requests to the API endpoints, it uses the [Requests](https://requests.readthedocs.io/en/latest/) library.
"""

# Import for getting the environmental variable values
import os
# Import for improved logging
import logging
# Import for adding delays to our HTTP requests
import time
# Import for sending and handling HTTP requests
import requests
# Import for loading .env files
from dotenv import load_dotenv
# Imports for utilities
import src.utils.constants as constants


def make_api_call(api_url: str, api_type: str) -> requests.Response:
    """Function to perform an API call to the given API url and source.

    In order to set the correct headers and/or parameters, this function
    needs to know which API provider it is sending a request to.

    Args:
        api_url (str): The URL to make the GET request to.
        api_type (str): The type of API to make the request to (GitHub or Libraries.io).

    Returns:
        response (requests.Response): The response from the GET request
    """

    # Make sure the environment variables are loaded
    load_dotenv(dotenv_path=constants.ENVIRON_FILE, override=True)

    data_response = None

    # Catch any requests errors
    try:
        # Basic request to get the information.
        if api_type == constants.API_GITHUB:
            data_response = requests.get(
                api_url, headers=get_needed_headers(api_type))
        elif api_type == constants.API_LIBRARIES:
            data_response = requests.get(
                api_url, params=get_needed_params(api_type))
    except requests.exceptions.RequestException as error:
        logging.error('Requests encountered an error:')
        logging.error(error)
        return None

    # See if we got a valid response
    if data_response.status_code == 200:
        return data_response
    # See if we got a rate limit error
    elif data_response.status_code == 429:
        # See if the header includes the rate limit reset time
        # If so, use it
        if 'Retry-After' in data_response.headers:
            retry_time = data_response.headers['Retry-After']
            logging.warning(
                f'Too many requests. Trying again in {retry_time} seconds.')
            time.sleep(retry_time)
            return make_api_call(api_url, api_type)
        # If not, use 30 seconds, as it is half the rate limit reset time
        else:
            logging.warning('Too many requests. Trying again in 30 seconds.')
            time.sleep(30)
            return make_api_call(api_url, api_type)
    elif (
        api_type == constants.API_GITHUB
        and data_response.status_code == 403
        and data_response.json()["documentation_url"]
        == "https://docs.github.com/free-pro-team@latest/rest/overview/rate-limits-for-the-rest-api#about-secondary-rate-limits"
    ):
        logging.warning('Reached secondary rate limit, retrying after 60 seconds.')
        time.sleep(60)
        return make_api_call(api_url, api_type)

    # Else, we got an unknown error so return None
    else:
        if api_type == constants.API_GITHUB:
            logging.error(
                f'Unable to get data from GitHub: {data_response.status_code}'
                + f'\n{api_url}\n{data_response.text}\n{data_response.headers}')
            return None
        elif api_type == constants.API_LIBRARIES:
            logging.error(
                f'Unable to get data from Libraries.io: {data_response.status_code}'
                + f'\n{api_url}\n{data_response.text}\n{data_response.headers}\n{api_type}')
            return None


def get_needed_headers(api_type: str) -> dict:
    """Function for getting the needed headers for the given API type.

    Args:
        api_type (str): The type of API to make the request to

    Returns:
        headers (dict): The headers to use for the request
    """

    if api_type == constants.API_GITHUB:
        gh_token = os.getenv(constants.GITHUB_TOKEN)

        if gh_token is not None:
            return {'Authorization': f'token {gh_token}', 'Accept': 'application/vnd.github.v3+json'}
        else:
            logging.error('Could not find GitHub token')
            return None
    else:
        return None


def get_needed_params(api_type: str) -> dict:
    """Function for getting the needed parameters for the given API type.

    Args:
        api_type (str): The type of API to make the request to

    Returns:
        params (dict): The parameters to use for the request
    """

    if api_type == constants.API_GITHUB:
        return None
    elif api_type == constants.API_LIBRARIES:
        lib_token = os.getenv(constants.LIBRARIES_TOKEN)

        if lib_token is not None:
            return {'api_key': lib_token}
        else:
            logging.error('Could not find Libraries.io token')
            return None
    else:
        return None


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

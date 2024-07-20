"""File for testing the integration tests between the Flask app and the Controller.

In order to test this, we need to make sure that any API call the Flask app receives
is passed onto the Controller correctly.
"""

# Imports for testing
import unittest.mock as mock
import pytest
# Import the Flask app
from app import app

# Set the testing client
client = app.test_client()


@pytest.mark.parametrize('json_input, return_value', [
    ({}, 'Token(s) not set! Please provide valid tokens.'),
    ({'github_token': 'gh_test_token'}, 'Github token set. '),
    ({'libraries_token': 'lib_test_token'}, 'Libraries token set.'),
    ({'github_token': 'gh_test_token', 'libraries_token': 'lib_test_token'},
     'Github token set. Libraries token set.')
])
class TestSetTokens:
    """Class containing the tests for the set_tokens route"""

    def test_set_keys(self, json_input: dict, return_value: str) -> None:
        """Function for testing the set_tokens function.

        The test is done by examining the returned text
        to see if it matches our expectations.

        Args:
            json_input (dict): A JSON object containing the possible permutations of token keywords for the APIs.
            return_value (str): A string denoting the final result of the function.
        """

        # Send a post request to the client
        response = client.post('/set_tokens', json=json_input)

        # Assert that the actual return value matches what we expected
        assert response.text is not None
        assert response.text == return_value


class TestGetTokens:
    """Class containing the tests for the get_tokens route"""

    def test_get_tokens(self) -> None:
        """Function for testing the get_tokens function.

        The test is done by actually reading the .env file for the currently stored tokens.
        We can do this as the tests for set_tokens create and update the .env file.
        """

        # Send a get request to the client
        response = client.get('/get_tokens')

        # Assert the response contains valid JSON
        assert response.is_json
        assert response.json is not None

        # Extract the json
        returned_json = response.json

        # Make sure the required keys are present
        assert 'github_token' in returned_json
        assert 'libraries_token' in returned_json

        # Make sure the returned values match what we are expecting
        assert returned_json['github_token'] == 'gh_test_token'
        assert returned_json['libraries_token'] == 'lib_test_token'


class TestGetData:
    """Class containing the tests for the get_data route"""

    @mock.patch('controller.Controller')
    def test_get_data(self, mock_controller: mock.Mock) -> None:
        """Function for testing the get_data function.

        The test is done by setting the return value of Controller.run() to a predetermined value.
        Then, we assert that the final returned value is equal to this predetermined value,
        as that means that the run() function has been called and returned the correct value.
        """

        # Set the return value of the run() function to a predetermined value
        mock_controller.return_value.run.return_value = {'returned': 'value'}

        # Execute the POST request
        result = client.post('/get_data', json={}).json

        # Make sure we get back the predetermined value
        assert result == {'returned': 'value'}


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

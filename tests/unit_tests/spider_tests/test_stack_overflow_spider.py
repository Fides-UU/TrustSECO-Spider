"""File containing the unit tests for the Stack_Overflow_calls.py file."""

# Unit testing imports
import pytest
# Import for sending and handling HTTP requests
import responses
# StackOverflow spider import
from src.stackoverflow.stackoverflow_api_calls import StackOverflowAPICall


class TestSOPopularity:
    """Class containing the tests for the Stack Overflow API call.

    To test this function, we shall test the following scenarios:
    1. The input parameters are valid.
    2. The input parameters are invalid:
      - Year is missing.
      - Month is missing.
      - TagPercents is missing.
      - Package is not in TagPercents.
    3. The response is invalid.
    """

    @responses.activate
    @pytest.mark.parametrize('return_json,return_json_pack,expected_value', [
        (
            {"total":100},
            {"total":0},
            0,
        ),
        (
            {"total":0},
            {"total":0},
            0,
        ),
        (
            {"total":100},
            {"total":20},
            20,
        ),
    ])
    def test_unknown_package(self, return_json: dict, return_json_pack: dict, expected_value: tuple) -> None:
        """Test for when the function receives an unknown package name.

        Args:
            return_json (dict): The json to return from the API call
            expected_value (tuple): The expected value of the function
        """

        # Create a Stack Overflow Call object
        stack_call = StackOverflowAPICall()

        # Add to responses
        responses.add(responses.GET, 'https://api.stackexchange.com/2.3/questions',
                      json=return_json, status=200)
        responses.add(responses.GET, 'https://api.stackexchange.com/2.3/questions',
                      json=return_json_pack, status=200)

        # Execute the function
        response_data = stack_call.get_monthly_popularity("package")

        # Check that the response is correct based on the given package name
        assert response_data == expected_value

    @responses.activate
    def test_invalid_response(self) -> None:
        """Test for when the function receives no response."""

        # Create a Stack Overflow Call object
        stack_call = StackOverflowAPICall()
        # Add to responses
        responses.add(responses.GET, 'https://api.stackexchange.com/2.3/questions',
                      json={'error': 'not found'}, status=404)

        # Execute the function
        response_data = stack_call.get_monthly_popularity('numpy')

        # Check that the response is correct based on the given package name
        assert response_data is None


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

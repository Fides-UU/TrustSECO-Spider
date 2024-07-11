"""File containing the setup for the Flask application.

Running this file will start the Flask application on the localhost at port 5000.

It then exposes the following endpoints:
- /get_data
- /set_tokens
- /get_tokens
"""

# Import for filesystem IO
import os
import sys
# Import for improved logging
import logging
# Import Flask
from flask import Flask, make_response, request
# Import JSON for pretty printing
import json
# Import for setting return-type
from responses import Response
# Import for setting parameter types
from typing import Tuple
# Import the controller of the TrustSECO-Spider
import controller
# Import CORS needed
from flask_cors import CORS
# Import for setting file permissions on startup
import subprocess


# Create the Flask application
app = Flask('app')
# Enable CORS
CORS(app)


# Set the route for data-retrieval
@app.post('/get_data')
def get_data() -> Response:
    """
    Uses the given JSON to get the wanted data-points.

    Returns:
        responses.Response: HTTP response containing the requested data as JSON
    """

    # Try to get the input json
    (is_valid, data) = try_get_json_input()
    if not is_valid:
        return data
    else:
        input_json = data

    # Inform the user of what is happening
    logging.info('Received the following JSON:')
    logging.info(json.dumps(input_json, indent=4))

    # Get the result from the spider
    result = controller.get_data(input_json)

    logging.info('Result:')
    logging.info(json.dumps(result, indent=4))

    # Return the result
    if 'Error' in result:
        response = make_response(result['Error'], 400)
        response.headers.set('Content-Type', 'text/plain')
    else:
        response = make_response(json.dumps(result), 200)
        response.headers.set('Content-Type', 'application/json')

    # Return the response
    return response


# Set the route for token setting
@app.post('/set_tokens')
def set_tokens() -> Response:
    """
    Uses the given JSON to set the tokens.

    Returns:
        responses.Response: HTTP response informing the user which keys were set using plain/text
    """

    # Try to get the input json
    (is_valid, data) = try_get_json_input()
    if not is_valid:
        return data
    else:
        input_json = data

    # Inform the user of what is happening
    logging.info('Setting tokens...')

    # Initialize an output string
    output = ''

    # If the github token is given, set it
    if 'github_token' in input_json:
        github_token = input_json['github_token']

        controller.update_token_gh(github_token)
        output += 'Github token set. '

    # If the library token is given, set it
    if 'libraries_token' in input_json:
        libraries_token = input_json['libraries_token']

        controller.update_token_lib(libraries_token)
        output += 'Libraries token set.'

    # Inform the user of what happened
    if output == '':
        output = 'Token(s) not set! Please provide valid tokens.'
        logging.warning(output)
    logging.info(output)

    # Return the output
    response = make_response(output)
    response.headers.set('Content-Type', 'text/plain')
    return response


@app.get('/get_tokens')
def get_tokens() -> Response:
    """
    Returns the tokens currently stored in the .env file

    Returns:
        responses.Response: HTTP request containing a JSON object with the TrustSECO-Spider's API tokens
    """

    # Get the tokens from the .env file
    tokens = controller.get_tokens()

    # Return the output
    response = make_response(tokens)
    response.headers.set('Content-Type', 'application/json')
    return response


def try_get_json_input() -> Tuple[bool, Response | dict]:
    """
    Tries to get the JSON input from the request.

    Returns:
        Tuple[bool, responses.Response | dict]: A tuple containing a bool that denotes whether or not the JSON input was valid,
        and either an HTTP response informing the user that something went wrong or the actual JSON input
    """

    # Make sure the request is JSON
    if not request.is_json:
        output = 'Error: Request was not of type application/json'
        logging.error(output)
        response = make_response(output, 400)
        response.headers.set('Content-Type', 'text/plain')
        return (False, response)

    # Get the input json
    input_json = request.get_json()

    # Make sure the input is valid
    if input_json is None:
        output = 'Error: Received JSON was invalid'
        logging.error(output)
        response = make_response(output, 400)
        response.headers.set('Content-Type', 'text/plain')
        return (False, response)

    # Return the input json only if it is valid
    return (True, input_json)


if __name__ == '__main__':
    # Set the permissions of the mounted volume (if needed)
    if os.path.exists('clamav/sockets/') and sys.platform != 'win32':
        result = subprocess.run(
            ['chmod', '777', 'clamav/sockets/'], capture_output=True)

    # Set the logging level
    logging.basicConfig(level=logging.DEBUG)

    # Start the Flask application
    app.run(host='0.0.0.0', port=5000, debug=False, use_evalex=False)

"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

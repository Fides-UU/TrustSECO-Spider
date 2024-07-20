# TrustSECO-Spider

This spider uses a combination of actual spidering (using BeautifulSoup) and API calls (using requests) in order to gather information from GitHub, Libraries.io, CVE and Stack Overflow. It can (if set up correctly) also scan for viruses within the files of a given project.

## GitHub

Our program retrieves most data-points using GitHub's REST API. Sadly, not all of the wanted data-points were accessible this way. In order to still gather this data, spidering had to be used.

It can currently get the following data-points from GitHub:

- Repository information:
	- Number of contributors
	- Number of users
	- Number of downloads
		- Per release
		- In total
	- Number of commits in the last year
	- Repository language
	- GitStar ranking
- Issues information:
	- Number of open issues
	- Number of issues without a response
	- Number of issues of a specific release
	- Ratio of open to closed issues
	- Average issue resolution time
- Owner information:
	- Number of stargazers

## Libraries.io

All of the data-points are gathered using various Libraries.io's APIs.

The currently available data-points are:

- Project:
	- Release frequency
	- Number of dependencies
	- Number of dependents
	- Number of releases
	- Latest release date
	- First release date
	- Sourcerank
- Repository:
	- Contributor count

## CVE

The spider can currently query the CVE service, and get all the known CVE codes of vulnerabilities of the given package.

For each of these codes, it can get the following information:

- CVE ID
- Vulnerability score
- Affected versions:
	- Start version
	- End version
	- The type thereof (inclusive or exclusive)

## Stack Overflow

The data-points that the spider is currently able to grab from Stack Overflow are:

- Trend popularity

## ClamAV virus scanner

The data-point that the virus scanner currently returns is the following:

- Virus ratio

This ratio is calculated by scanning all available files within a release, and dividing the amount of virus-containing files by the total amount of files.

## How to use

### Requirements

In order to run our program, certain python libraries will have to be installed. This can easily be done by running the `pip install -r requirements.txt` command from within the `TrustSECO-Spider` folder.

**THIS IS ONLY NEEDED IF RUNNING THE SPIDER AS A STANDALONE SERVICE. IF RUNNING WITHIN DOCKER,  THIS STEP CAN BE SKIPPED**

### Running as a service

#### Standalone

As the other sub-projects will need to request data from the spider, flask was used in order to create an endpoint for this. In order to run the TrustSECO-Spider as a (development) service, simply run `python .\app.py` command from within the `TrustSECO-Spider` folder.
This will run a local server on the following address: `http://localhost:5000`.

For this to work, you will have to manually enter your GitHub and Libraries.io tokens into the .env file.

##### Finding the tokens

The GitHub token can be generated under `Settings -> Developer settings -> Personal access tokens`. The needed token does not need any of the selectable scopes.

The Libraries.io token can be found under `Settings -> API Key` after logging in.

##### Entering the tokens

The tokens have to be added to a file called `.env` which must be located within the `TrustSECO-Spider` folder. The file should look like this:

```Python
GITHUB_TOKEN=''
LIBRARIES_TOKEN=''
```

Where of course the empty strings must be replaced with your tokens.

#### Docker

Alternatively, the recommended way of running the TrustSECO-Spider is by running it within a Docker container. To do this, you must first install and start up Docker, as otherwise you will not have access to the needed commands.

After Docker is ready, simply open a terminal window within the `TrustSECO-Spider` folder. Now, there are two different ways of running the Spider, either with or without running the virus scan service. 

If you do need the virus scan capabilities, only one command has to be run:

1. `docker-compose up` -> Uses the configuration specified within the 'docker-compose.yml' file to start up the TrustSECO-Spider and the ClamAV virus scanner.

If you don't need the virus scan capabilities, please perform the following commands:

1. `docker build . -t spider-image` -> This will create a Docker image with the name "spider-image"
2. `docker run --name 'TrustSECO-Spider' spider-image` -> This will create a Docker container based off of the Docker image you just made. It will also set the name of the container to 'TrustSECO-Spider' for easy identification.

### Setting API tokens

After running the program as a service as described above, the API tokens for GitHub and Libraries.io must be set. This can be done by sending a POST request to `http://localhost:5000/set_tokens`. This POST request **MUST** contain the following:

1. A header with the content-type set as `application/json`.
2. A JSON input following the schemas found in the `JSON schemas` folder. The relevant JSON file would be `token_input.json`.

An example of this (using `python` and the `requests` library) would be the following:

``` Python
header = {'Content-type':'application/json'}

input_json = {
  'github_token': 'gho_jeshfuehfhsjfe',
  'libraries_token': 'jdf9328bf87831bfdjs0823'
}

response = requests.post('http://localhost:5000/set_tokens', headers={'Content-type':'application/json'}, json=input_json)

print(response.text)
```

*Naturally, the tokens provided here are fake, and must be replaced with your own.*

If only 1 token has to be set/updated, only that 1 token needs to be supplied.

### Getting API tokens

If needed, the API tokens that the TrustSECO-Spider is currently using can be requested. This can simply be done by sending a GET request to `http://localhost:5000/get_tokens`. Example:

``` Python
response = requests.GET('http://localhost:5000/set_tokens')

print(response.json())
```

### Requesting data

This address can then be used in order to request data. This is done by sending a POST request to the endpoint. This POST request **must** contain the following:

1. A header with the content-type set as `application/json`.
2. A JSON input following the schemas found in the `JSON schemas` folder. The relevant JSON files would be `input_example.json` and `input_structure.json`.

An example of this (using `python` and the `requests` library) would be the following:

``` Python
header = {'Content-type':'application/json'}

input_json = {
  'project_info': {
    'project_platform': 'Pypi',
    'project_owner': 'numpy',
    'project_name': 'numpy',
    'project_release': 'v.1.22.1',
  },
  'cve_data_points': [
    'cve_count',
    'cve_vulnerabilities',
    'cve_codes'
  ]
}

response = requests.post('http://localhost:5000/get_data', headers={'Content-type':'application/json'}, json=json_input)

print(response.json())
```

#### Virus scanning

The TrustSECO-Spider also has the ability to scan URLs for viruses. The URLs will be retrieved automatically based off of the project information you give the TrustSECO-Spider.

**WARNING: YOU NEED TO FOLLOW THE SECOND SET OF INSTRUCTIONS WITHIN THE 'Docker' INSTALLATION SECTION TO MAKE SURE THE VIRUS SCANNER IS RUNNING**

**IT CAN TAKE A WHILE FOR THE VIRUS SCANNER TO START UP, SO PLEASE WATCH THE LOG TO MAKE SURE IT IS DONE. THE FINAL MESSAGE SHOULD BE: 'xxx.cvd database is up-to-date'**

You can request for the scanning of viruses by performing almost the same steps as in the 'Requesting data' section, however, another field had to be added within the `input_json` object like so:

``` Python
header = {'Content-type':'application/json'}

input_json = {
  'project_info': {
    'project_platform': 'Pypi',
    'project_owner': 'numpy',
    'project_name': 'numpy',
    'project_release': 'v.1.22.1',
  },
  "virus_scanning": [
    "vs_virus_ratio"
  ]
}
```

Other than that added field, the instructions remain the same as in 'Requesting data'.

### Return values

Depending on which end-point you send a request to (`get_data`, `set_tokens` or `get_tokens`), a certain type of response will be sent.

In case of `get_data`, the return type will change depending on whether or not the request succeeded. For example, if the request did not contain all the needed information, the return type would be `Content-type: text/plain` and would contain the reason for the failure (in this case `Error: missing project information`).

If the request did succeed, the return type would be `Content-type: application/json`, and the response would include the wanted data in a JSON format.

In case of `set_tokens`, it will always return `Content-type: text/plain`.

In case of `get_tokens`, the return type will always be `Content-type: application/json`. The JSON structure is the same as what is described within 'token_input.json'.

Please use the content type to avoid trying to grab non-existent JSON data or text.

### Demo

This project also contains a small demo file (demo.py) which can demo basic functionality. Simply enter `python .\demo.py` in the command line in order to get a list of possible arguments. With these arguments you can specify which of the demos to run.

**IMPORTANT: The Flask service must be started before running the demo, and the tokens must be set in the .env file beforehand too!!!**

**MAKE SURE THE VIRUS SCANNER IS RUNNING BEFORE ASKING FOR VIRUS-SCAN DATA**

### Unit tests

The project also contains some of the unit tests too. These can be started from within the main `TrustSECO-Spider` folder using the `python -m pytest` command in the console.

**IMPORTANT: the tokens within the .env file must be removed before running the tests, as they will overwrite the test variables!!!**

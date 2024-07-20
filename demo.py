"""File containing the demonstration code for the TrustSECO-Spider.

This file can be run in order to test the TrustSECO-Spider. When running this file
without any arguments, it will print a list of possible arguments to the console.
Please use these in order to customize the demonstration to your needs.

**Before running this file, the Flask application needs to be started. (instructions for which can be found in the README.md file)**
"""
# Import for getting input parameters
import sys
# Import for pretty printing the JSON data
import json
# Import for sending and handling HTTP requests
import requests
# Import the ClamAV scanner
from src.clamav.clamav_scanner import ClamAVScanner

gh_dict = {
    "gh_data_points": [
        "gh_contributor_count",
        "gh_user_count",
        "gh_total_download_count",
        "gh_release_download_count",
        "gh_yearly_commit_count",
        "gh_repository_language",
        "gh_open_issues_count",
        "gh_zero_response_issues_count",
        "gh_issue_ratio",
        "gh_average_resolution_time",
        "gh_owner_stargazer_count"
    ]
}

lib_dict = {
    "lib_data_points": [
        "lib_release_frequency",
        "lib_contributor_count",
        "lib_dependency_count",
        "lib_dependent_count",
        "lib_latest_release_date",
        "lib_first_release_date",
        "lib_release_count",
        "lib_sourcerank"
    ]
}

cve_dict = {
    "cve_data_points": [
        "cve_count",
        "cve_vulnerabilities",
        "cve_codes"
    ]
}

so_dict = {
    "so_data_points": [
        "so_popularity"
    ]
}

virus_dict = {
    "virus_scanning": [
        "vs_virus_ratio"
    ]
}


def numpy_demo(wanted_data_points: dict) -> None:
    """Function for testing the TrustSECO-Spider on the numpy repository.

    Args:
        wanted_data_points (dict): Dictionary containing the wanted data-points.
    """

    # Set the input JSON
    input_json = {
        "project_info": {
            "project_platform": "Pypi",
            "project_owner": "numpy",
            "project_name": "numpy",
            "project_release": "v1.22.1",
        }
    }

    # Add the wanted data points to the input JSON
    input_json.update(wanted_data_points)

    try:
        # Get the data
        response_data = requests.post('http://localhost:5000/get_data',
                                      headers={'Content-type': 'application/json'}, json=input_json).json()

        # Print the data
        if response_data is not None:
            print(json.dumps(response_data, indent=4))
        else:
            print("No data found, perhaps you did not set your API tokens?")
    except Exception:
        print('Error: Could not connect to the TrustSECO-Spider API.')
        print('Make sure the API is running and the API tokens are set.')


def afnetworking_demo(wanted_data_points: dict) -> None:
    """Function for testing the TrustSECO-Spider on the AFNetworking repository.

    Args:
        wanted_data_points (dict): Dictionary containing the wanted data-points.
    """

    # Set the input JSON
    input_json = {
        "project_info": {
            "project_platform": "CocoaPods",
            "project_owner": "AFNetworking",
            "project_name": "AFNetworking",
            "project_release": "4.0.0",
        }
    }

    # Add the wanted data points to the input JSON
    input_json.update(wanted_data_points)

    try:
        # Get the data
        response_data = requests.post('http://localhost:5000/get_data',
                                      headers={'Content-type': 'application/json'}, json=input_json).json()

        # Print the data
        if response_data is not None:
            print(json.dumps(response_data, indent=4))
        else:
            print("No data found, perhaps you did not set your API tokens?")
    except Exception:
        print('Error: Could not connect to the TrustSECO-Spider API.')
        print('Make sure the API is running and the API tokens are set.')


def virus_free_demo() -> None:
    """Function for testing the ClamAV container using known virus-free files.

    The files in question are taken from the "numpy" repository.
    """

    # Setup the scanner
    sc = ClamAVScanner()

    # Scan the given file links
    ratio = sc.get_virus_ratio([
        'https://github.com/numpy/numpy/releases/download/v1.22.4/1.22.4-changelog.rst',
        'https://github.com/numpy/numpy/releases/download/v1.22.4/numpy-1.22.4.tar.gz',
        'https://github.com/numpy/numpy/releases/download/v1.22.4/numpy-1.22.4.zip',
        'https://github.com/numpy/numpy/releases/download/v1.22.4/README.rst',
        'https://github.com/numpy/numpy/archive/refs/tags/v1.22.4.zip',
        'https://github.com/numpy/numpy/archive/refs/tags/v1.22.4.tar.gz'
    ])

    # Print the resulting ratio
    print(f'Virus ratio: {ratio}')


def virus_infected_demo() -> None:
    """Function for testing the ClamAV container using known dummy-virus-infected files.

    The file that's used for this test contains various EICAR-containing files.
    EICAR is a type of anti-virus test file that is used to test virus-scanners.
    For more information, see: [EICAR Wikipedia page](https://www.wikiwand.com/en/EICAR_test_file)
    """

    # Setup the scanner
    sc = ClamAVScanner()

    # Scan the given file link
    ratio = sc.get_virus_ratio([
        'https://github.com/fire1ce/eicar-standard-antivirus-test-files/archive/refs/heads/master.zip'
    ])

    # Print the resulting ratio
    print(f'Virus ratio: {ratio}')


if __name__ == '__main__':
    # See if the user passed arguments
    if len(sys.argv) > 1:

        # Get the wanted data-points
        wanted_data_points = {}
        if 'g' in sys.argv:
            wanted_data_points.update(gh_dict)
        if 'l' in sys.argv:
            wanted_data_points.update(lib_dict)
        if 'c' in sys.argv:
            wanted_data_points.update(cve_dict)
        if 's' in sys.argv:
            wanted_data_points.update(so_dict)
        if 'v' in sys.argv:
            wanted_data_points.update(virus_dict)

        # If numpy is specified, run the numpy demo
        if 'numpy' in sys.argv or 'all' in sys.argv:
            numpy_demo(wanted_data_points)

        # If afnetworking is specified, run the afnetworking demo
        if 'afnetworking' in sys.argv or 'all' in sys.argv:
            afnetworking_demo(wanted_data_points)

        # If virus_s is specified, run the safe virus demo
        if 'virus_s' in sys.argv:
            virus_free_demo()

        # If virus_i is specified, run the infected virus demo
        if 'virus_i' in sys.argv:
            virus_infected_demo()
    else:
        print('No arguments passed.')
        print('Please specify which library you would like to gather data of:')
        print('\t- numpy')
        print('\t- afnetworking')
        print('\t- all')
        print('Please specify which data-sources you would like to gather data from:')
        print('\t- g (GitHub)')
        print('\t- l (Libraries.io)')
        print('\t- c (CVE)')
        print('\t- s (Stack Overflow)')
        print('\t- v (Virus scanner)')
        print('Alternatively, if you only want to test the virus-scanner, enter only these arguments:')
        print('\t- virus_s (safe)')
        print('\t- virus_i (infected)')
        print('Using the virus-scanner requires the ClamAVScanner to be installed.')


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

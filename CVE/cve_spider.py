"""
Allow the program to use BeautifulSoup and Requests in order to
scrape wanted data-points from the CVE website.
"""

import json
import requests
from bs4 import BeautifulSoup


class CVESpider:
    """
    Class methods for getting data from the CVE website using BeautifulSoup and requests for spidering
    """

    def get_cve_vulnerability_count(self, name):
        """
        Gets the amount of known vulnerabilities of a given package
        """

        # Get the list of CVE links
        cve_codes = self.get_cve_codes(name)

        # Return the list of CVE data
        if cve_codes is not None:
            return len(cve_codes)
        else:
            return None

    def get_all_cve_data(self, name):
        """
        Loops through all the found CVE vulnerabilities, and extracts the data
        """

        # Get the list of CVE links
        cve_codes = self.get_cve_codes(name)

        # make sure we actually got a result back
        if cve_codes is not None:
            # Initialise the list of CVE data
            data = []
            # Go through all the links and extract the CVE data
            for cve_code in cve_codes:
                cve_data = self.extract_cve_data(cve_code)
                if cve_data is not None:
                    data.append(cve_data)

            # Return the list of CVE data
            return data
        else:
            return None

    def get_cve_codes(self, name):
        """
        Searches through the CVE database for the given package name

        Returns a list of CVE codes for vulnerabilities affecting the given package
        """

        # Create the URL for the package
        cve_link = f'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={name}'

        # Get a soup object of the CVE webpage
        soup = self.get_and_parse_webpage(cve_link)

        # Make sure we got a valid result
        if soup is None:
            return None

        # Find the <a> tags that contain the CVE links
        tables = soup.find_all('table')
        # See if the wanted table exists
        if tables is not None:
            if len(tables) == 5:
                table = tables[2]
                links = table.find_all('a')

                # Return the list of CVE codes
                cve_codes = []
                for link in links:
                    cve_codes.append(link.text)

                # Return the list of CVE codes
                return cve_codes
            else:
                return None
        else:
            return None

    def extract_cve_data(self, cve_code):
        """
        Extracts the data from a given CVE link

        The data we extract is:
        - CVE code
        - CVE score
        - Affected versions:
          - Start version type
          - Start version
          - End version type
          - End version
        """

        # Create the full URL for the CVE link
        full_url = f'https://nvd.nist.gov/vuln/detail/{cve_code}'

        # Get a soup object of the CVE webpage
        soup = self.get_and_parse_webpage(full_url)

        # Make sure we got a valid result
        if soup is None:
            return None

        # get the vulnerability score
        score_element = soup.find(id='Cvss3NistCalculatorAnchor')
        # Make sure we got a valid result
        score = None
        if score_element is not None:
            # Parse the score string
            score = float(score_element.text.split(' ')[0])

        # Get the affected versions
        affected_version_start_type = None
        affected_version_start = None
        affected_version_end_type = None
        affected_version_end = None
        try:
            json_data = json.loads(
                soup.find(id='cveTreeJsonDataHidden')['value'])
            # Go to the location of the data within the JSON object
            data = json_data[0]['containers'][0]['cpes'][0]
            # Get the information about the affected versions
            affected_version_start_type = None
            if data['rangeStartType'] != 'none':
                affected_version_start_type = data['rangeStartType']

            affected_version_end_type = None
            if data['rangeEndType'] != 'none':
                affected_version_end_type = data['rangeEndType']

            affected_version_start = data['rangeStartVersion']
            affected_version_end = data['rangeEndVersion']
        except Exception as e:
            print('Could not find affected versions.')
            print(e)

        # Put the extracted data into a dictionary
        cve_data = {
            'CVE_ID': cve_code,
            'CVE_score': score,
            'CVE_affected_version_start_type': affected_version_start_type,
            'CVE_affected_version_start': affected_version_start,
            'CVE_affected_version_end_type': affected_version_end_type,
            'CVE_affected_version_end': affected_version_end,
        }

        # Return the CVE data
        return cve_data

    def get_and_parse_webpage(self, url):
        """
        Gets the HTML of a given webpage and converts it into a BeautifulSoup object
        """

        try:
            # Make a GET request to the given URL
            html = requests.get(url)
            if html.status_code != 200:
                raise requests.exceptions.RequestException(
                    'Could not load the webpage')
        except requests.exceptions.RequestException as e:
            print('Error loading webpage.')
            print(e)
            return None

        try:
            # Convert the raw HTML into a BeautifulSoup object
            soup = BeautifulSoup(html.text, 'html.parser')
        except Exception as e:
            print('Error parsing the webpage.')
            print(e)
            return None

        # Return the BeautifulSoup object
        return soup

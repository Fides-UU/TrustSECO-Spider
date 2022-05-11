"""File containing the GitHub spider

This file contains the logic for the spider that will
allow the program to use BeautifulSoup and Requests
in order to scrape wanted data-points from the GitHub website.

    Typical usage:

    foo = GitHubSpider()
    bar = foo.get_repository_user_count('owner', 'repo')
"""

from bs4 import BeautifulSoup
import requests


class GitHubSpider:
    """Class methods for getting data from the GitHub website

    This class handles all of the spidering jobs for the GitHub website.
    It uses requests to get the webpage, and BeautifulSoup to parse and traverse it.
    """

    def get_repository_user_count(self, owner, repo) -> int:
        """
        Get the number of users of a given repository

        Parameters:
            owner (str): The owner of the repository
            repo (str): The repository

        Returns:
            int: The number of users of the repository
        """

        # Create the URL for the repository
        main_page_url = f'https://github.com/{owner}/{repo}'

        # Get the main page
        main_page = requests.get(main_page_url)

        # Make sure the main page is valid
        if main_page.status_code != 200:
            return None

        # Create a BeautifulSoup object
        soup = BeautifulSoup(main_page.text, 'html.parser')

        # Get the <a> tags that might contain our number
        possible_links = soup.find_all(
            'a', class_='Link--primary no-underline')

        # Initialise the counter to None
        user_count = None
        # Go through all the <a> tags and find the one containing "Used by"
        # as this is the one containing the number of users
        for link in possible_links:
            if 'used by' in link.text.lower():
                value = link.span.get('title')
                if value is not None:
                    # Remove unwanted characters
                    value = value.replace(',', '').replace('\n', '').strip()
                    # Convert to integer
                    user_count = int(value.split(' ')[0])
                    # Break as we have found our wanted node
                    break

        return user_count

    def get_repository_open_issue_count(self, owner, repo) -> int:
        """
        Get the amount of open issues of a given repository

        Parameters:
            owner (str): The owner of the repository
            repo (str): The repository

        Returns:
            int: The number of open issues of the repository
        """

        # Create the URL for the repository
        issues_page_url = f'https://github.com/{owner}/{repo}/issues'

        # Get the issues page
        issues_page = requests.get(issues_page_url)

        # Make sure the main page is valid
        if issues_page.status_code != 200:
            return None

        # Create a BeautifulSoup object
        soup = BeautifulSoup(issues_page.text, 'html.parser')

        # Get the <a> tags that might contain our numbers
        possible_links = soup.find_all('a', class_='btn-link')

        # Try to find the open issues count
        open_issues = None
        # Go through all the <a> tags and find the ones containing "open"
        # as these are the ones containing the number of issues
        for link in possible_links:
            if 'open' in link.text.lower():
                value = link.text.replace(',', '').replace('\n', '').strip()
                open_issues = int(value.split(' ')[0])

            # If we have found the number, return it
            if open_issues is not None:
                return open_issues

        # Else return None
        return None

    def get_repository_closed_issue_count(self, owner, repo) -> int:
        """
        Get the amount of closed issues of a given repository

        Parameters:
            owner (str): The owner of the repository
            repo (str): The repository

        Returns:
            int: The number of closed issues of the repository
        """

        # Create the URL for the repository
        issues_page_url = f'https://github.com/{owner}/{repo}/issues'

        # Get the issues page
        issues_page = requests.get(issues_page_url)

        # Make sure the main page is valid
        if issues_page.status_code != 200:
            return None

        # Create a BeautifulSoup object
        soup = BeautifulSoup(issues_page.text, 'html.parser')

        # Get the <a> tags that might contain our numbers
        possible_links = soup.find_all('a', class_='btn-link')

        # Try to find the closed issues count
        closed_issues = None
        # Go through all the <a> tags and find the ones containing "closed"
        # as these are the ones containing the number of issues
        for link in possible_links:
            if 'closed' in link.text.lower():
                value = link.text.replace(',', '').replace('\n', '').strip()
                closed_issues = int(value.split(' ')[0])

            # If we have found the number, return it
            if closed_issues is not None:
                return closed_issues

        # Else return None
        return None

    def get_repository_issue_ratio(self, owner, repo) -> float:
        """
        Get the issue ratio of a given repository

        Parameters:
            owner (str): The owner of the repository
            repo (str): The repository

        Returns:
            float: The issue ratio of the repository
        """

        # Get the issue counts
        open_issues = self.get_repository_open_issue_count(owner, repo)
        closed_issues = self.get_repository_closed_issue_count(owner, repo)

        # If we could not find both numbers,
        # or if the closed issue count is 0,
        # return None
        if open_issues is None or closed_issues is None or closed_issues == 0:
            return None
        # Else return the ratio
        else:
            return open_issues / closed_issues


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

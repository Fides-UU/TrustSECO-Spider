"""File containing the Stack Overflow API call processor.

This file contains the logic for crawling through the [Stack Overflow website](https://stackoverflow.com/).

This API calls are done by using the [Requests](https://requests.readthedocs.io/en/latest/) library.
"""

import logging
from datetime import datetime, timedelta, timezone
import requests
from typing import Any


class StackOverflowAPICall:
    """Class methods for getting data from Stack Overflow"""

    def get_monthly_popularity(self, package: str) -> float | None:
        """Function to get the monthly popularity of a package.

        The data is retrieved from the stack exchange api.

        Args:
            package (str): The name of the package.

        Returns:
            float: The popularity in the latest 30 days of the package. This popularity
                is the percentage of questions posted that were about the given package.
        """
        logging.info("Getting monthly popularity")
        # Time stamp 30 days ago in unix epoch time
        from_time = (
            datetime.now(timezone.utc)
            - datetime(1970, 1, 1, tzinfo=timezone.utc)
            - timedelta(days=30)
        ).total_seconds()

        # request url to get all questions from last month
        url_total = f"https://api.stackexchange.com/2.3/questions?fromdate={round(from_time)}&site=stackoverflow&filter=total"
        # request url to get all questions for this package from last month
        url_package = f"{url_total}&tagged={package}"

        # If both requests were succesfull calculate percentage and return
        if (resp_total := self.make_stackoverflow_request(url_total)) and (
            resp_package := self.make_stackoverflow_request(url_package)
        ):
            total = resp_total["total"]
            total_package = resp_package["total"]
            if total_package == 0:
                return 0
            return (total_package / total) * 100
        else:
            return None

    def make_stackoverflow_request(self, url: str) -> Any | None:
        """Performs a request to the stackexchange api

        Args:
            url (str): full url to requests

        Returns:
            Any | None: The json content of the response, none if an error occured
        """
        # NOTE: using api keys would be better, but there is rate limit of
        # 10000 requests per ip so no keys should be fine.
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.json()
            return None
        except requests.exceptions.RequestException as e:
            logging.error(e)
            return None


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

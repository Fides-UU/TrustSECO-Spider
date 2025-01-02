from typing import Iterable
import itertools
import re
import logging

import requests

from src.utils.api_calls import make_api_call
import src.utils.constants as constants


github_regex = re.compile(r"https://github\.com/([^/]+)/([^/]+)")


def get_most_popular_packages(platform: str, count: int) -> list[dict]:
    """Gets the most popular packages packages for a particular platform

    Example data:
    [
        {
            "name": "numpy",
            "platform": "pypi",
            "owner": "pypi",
            "version": "1.0.2"
        }
    ]
    """
    packages = itertools.islice(get_most_popular_packages_pypi(), count)
    return list(filter(None, map(lambda p: get_package_data(p, platform), packages)))


def get_most_popular_packages_pypi() -> Iterable[str]:
    """Get a list of the most popular packages of the last 30 days from a json
    dump."""
    resp = requests.get(
        "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
    )
    resp.json()
    return (row["project"] for row in resp.json()["rows"])


def get_package_data(name: str, platform: str) -> dict | None:
    """Takes a package name and returns a dict with additional package
    information: repository owner and most recent version."""
    repo_url = get_repo_link(name, platform)
    if not repo_url:
        return None
    match = github_regex.match(repo_url)
    if match is not None:
        (owner, name_git) = match.group(1, 2)
    else:
        return None
    if name_git != name:
        logging.warning(f"name not same as repo name {name} {name_git}")
        return None
    version = get_most_recent_version(name_git, owner, platform)
    return {
        "name": name,
        "platform": platform,
        "owner": owner,
        "version": version
    }


def get_repo_link(name: str, platform: str) -> str | None:
    """Get the repository link of a package."""
    url = f"https://libraries.io/api/{platform}/{name}"
    resp = make_api_call(url, constants.API_LIBRARIES)
    if not resp:
        return None
    return resp.json()["repository_url"]


def get_most_recent_version(name: str, owner: str, platform: str) -> str:
    """Get the most recent version of a package from cosy."""
    url = "http://web:3000/api/dlt/get-most-recent-version/"
    json = {
        "name": name,
        "platform": platform,
        "owner": owner,
    }
    return requests.post(url, json, timeout=10, verify=False).text

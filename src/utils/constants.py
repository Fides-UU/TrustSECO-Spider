"""File containing the constants used throughout the TrustSECO-Spider."""

# Program wide constants
API_GITHUB = 'GitHub'
"""Enumeration for the GitHub API type"""
API_LIBRARIES = 'Libraries.io'
"""Enumeration for the Libraries.io API type"""

GITHUB_TOKEN = 'GITHUB_TOKEN'
"""Environment variable name for the GitHub token"""
LIBRARIES_TOKEN = 'LIBRARIES_TOKEN'
"""Environment variable name for the Libraries.io token"""

# GitHub Constants
# Base URLs for the GitHub API
BASE_URL_REPOS = 'https://api.github.com/repos'
"""Base URL for the GitHub repository API"""
BASE_URL_USERS = 'https://api.github.com/users'
"""Base URL for the GitHub user API"""
BASE_URL_SEARCH = 'https://api.github.com/search'
"""Base URL for the GitHub search API"""
BASE_URL_ORGS = 'https://api.github.com/orgs'
"""Base URL for the GitHub organizations API"""
BASE_URL_RATE = 'https://api.github.com/rate_limit'
"""Base URL for the GitHub rate limit API"""
# API call types
CORE = 'core'
"""Enumeration for the core API call type"""
SEARCH = 'search'
"""Enumeration for the search API call type"""
RATE = 'rate'
"""Enumeration for the rate limit API call type"""

# Authentication Constants
ENVIRON_FILE = '.env'
"""Environment file path"""

"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

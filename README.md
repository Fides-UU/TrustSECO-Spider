# TrustSECO-Spider
This spider uses a combination of actual spidering (using BeautifulSoup) and API calls (using requests) in order to gather information from GitHub and Libraries.io.

## GitHub
Our program uses GitHub's Device Flow in order to obtain a personal token, which then gets used for the API calls.

It retrieves most data-points using GitHub's REST API. Sadly, not all of the wanted data-points were accessible this way. In order to still gather this data, spidering had to be used.

It can currently get the following data-points from GitHub:
- Repository information:
  - Number of contributors
  - Number of users
  - Number of downloads
    - Per release
    - In total
  - Number of commits per year:
    - In the past year from the current date
    - In a specific year
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
As Libraries.io does not have a 'Device Flow' like way to obtain a personal token, the user will have to enter this manually when starting the program.

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

## How to use
### Requirements
As a fair amount of library imports are needed for this project, we have included a PIP compatible requirements file which can be used to automatically download all the needed packages. Simply use the command ```pip install -r requirements.txt```.

### Demo
This project also contains a small demo file (demo.py) which can demo basic functionality. Simply enter ```python .\demo.py``` in the command line in order to run the demo. It will then query/find all of the Libraries.io data-points, and the GitHub data-points that do not use the SEARCH API. This is because GitHub's SEARCH API has a far lower rate limit than its CORE API.
If desired, the SEARCH functions can also be demo'd. To do this, simply add ```gh_search``` as the parameter like this: ```python .\demo.py gh_search```.

### Unit tests
The project also contains some of the unit tests too. These can be started from within the main ```TrustSECO-Spider``` folder using the ```python -m pytest``` command in the console.
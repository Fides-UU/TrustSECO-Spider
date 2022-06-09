"""File containing the communication between the TrustSECO-Spider and the virus scanner."""

# Import os to allow for file checking and console usage
from subprocess import run, TimeoutExpired
import os


class ScannerCommunication:
    """ Class methods for scanning web links that direct to files for viruses. """

    def get_virus_ratio(self, links) -> float:
        """
        Scans the given links' contents for viruses.

        Parameters:
            links (list): List of web links to the files to scan.

        Returns:
            float: Percentage of links that have been scanned for viruses.
        """

        # Make sure we have a list of links
        if links is None:
            print('No links provided. (None input)')
            return None
        if len(links) == 0:
            print('No links provided. (empty list)')
            return None

        # Make sure the UNIX socket is available for clamdscan
        if not self.check_socket_availability():
            return None

        # Initialize a counter for the number of infected links found
        infected_links = 0

        # Iterate through the links
        for link in links:
            # Scan the link
            result = self.scan_link(link)

            # If None was returned, a problem was encountered so we can return None
            if result is None:
                return None
            # Else, if the result returned True, then a virus was found, and the counter should be incremented
            elif result:
                # Increment the counter if a virus has been detected
                infected_links += 1

        # Return the percentage of links that have been scanned for viruses
        return infected_links / len(links)

    def scan_link(self, link) -> bool:
        """
        Scans the given link's contents for viruses.

        Parameters:
            link (str): Web link to the file to scan.

        Returns:
            bool: True if a virus has been detected, False otherwise.
        """

        # Open a command stream with the clamdscan command
        stream = os.popen(
            f'wget -qO- {link} | clamdscan --config-file=clamav/client_clamd.conf -')
        # Get the output of the scan
        feedback = stream.readlines()
        # Close the stream
        stream.close()

        # Try to extract the virus count from the output
        virus_count = None
        for line in feedback:
            if 'Infected files' in line:
                virus_count = line.strip().split(': ')[1]

        # Return True if a virus has been detected, False otherwise
        if virus_count is None:
            return None
        elif virus_count == '0':
            return False
        else:
            return True

    def check_socket_availability(self) -> bool:
        """Function to check whether or not the socket file exists, and is accepting connections."""

        # See if the file-path exists
        if not os.path.exists('clamav/sockets/clamd.sock'):
            print('The UNIX socket file does not exist.')
            return False

        # See if the UNIX socket is listening to requests
        try:
            run('socat -u OPEN:/dev/null UNIX-CONNECT:clamav/sockets/clamd.sock',
                shell=True, timeout=1)
        except Exception as e:
            if type(e) is not TimeoutExpired:
                print(e)
                return False

        return True


"""
This program has been developed by students from the bachelor Computer Science at Utrecht University within the Software Project course.
© Copyright Utrecht University (Department of Information and Computing Sciences)
"""

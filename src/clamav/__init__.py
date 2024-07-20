"""
In order to implement the virus-scanner feature, a new Docker container needed to be created and communicated with.
The container creation is handled by CoSy (or Docker Compose if running the TrustSECO-Spider on its own).

This then leaves the communication aspect. The communication is implemented within this module.
Currently, the only virus-scanner is ClamAV, but this can be expended upon simply by adding another class in this module.
"""

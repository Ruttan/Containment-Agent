"""
Base connector — defines the interface every platform adapter must follow.
When you add a new platform, create a new file in this folder and inherit from BaseConnector.
"""

from abc import ABC, abstractmethod


class BaseConnector(ABC):
    """
    Every platform connector must implement these two methods.
    The agent calls these without knowing which platform is underneath.
    """

    @abstractmethod
    def isolate_host(self, host_id: str) -> dict:
        """
        Isolate (network-quarantine) a host by its ID.
        Returns a dict with keys:
          - success (bool)
          - message (str)
          - raw_response (dict, optional)
        """
        pass

    @abstractmethod
    def get_host_info(self, host_id: str) -> dict:
        """
        Retrieve basic info about a host for display in the approval notification.
        Returns a dict with keys:
          - hostname (str)
          - ip_address (str)
          - os (str)
          - last_seen (str)
        """
        pass

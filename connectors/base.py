"""
Base connector — defines the interface every platform adapter must follow.
When you add a new platform, create a new file in this folder and inherit from BaseConnector.
"""

from abc import ABC, abstractmethod


class BaseConnector(ABC):
    """
    Every platform connector must implement isolate_host() and get_host_info().
    kill_process(), quarantine_file(), and block_hash() are optional response
    actions — override them if the platform API supports them. The default
    implementations here return a "not supported" result so the agent can
    still function (and the notifier will simply not offer that action button)
    for platforms/connectors that don't implement it.

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

    # ------------------------------------------------------------------
    # Optional response actions.
    # Override in a subclass if the platform API supports the action.
    # All must return: {"success": bool, "message": str, "raw_response": dict}
    # ------------------------------------------------------------------

    def kill_process(self, host_id: str, process_id: str) -> dict:
        """Terminate a running process on the host by PID (or process GUID, platform-dependent)."""
        return self._not_supported("kill_process")

    def quarantine_file(self, host_id: str, file_path: str = None, file_hash: str = None) -> dict:
        """Quarantine a specific file on the host, identified by path and/or hash."""
        return self._not_supported("quarantine_file")

    def block_hash(self, file_hash: str) -> dict:
        """Add a file hash to the platform's block/deny list (org-wide indicator block)."""
        return self._not_supported("block_hash")

    def _not_supported(self, action: str) -> dict:
        return {
            "success": False,
            "message": f"{action} is not supported by the {self.__class__.__name__}.",
            "raw_response": {},
        }

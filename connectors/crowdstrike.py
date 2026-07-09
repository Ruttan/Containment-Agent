"""
CrowdStrike Falcon connector.
Uses the Hosts and Real-time Response APIs to isolate endpoints.

Required config fields:
  platforms.crowdstrike.client_id
  platforms.crowdstrike.client_secret
  platforms.crowdstrike.base_url
"""

import requests
from .base import BaseConnector


class CrowdStrikeConnector(BaseConnector):

    def __init__(self, config: dict):
        cs_cfg = config["platforms"]["crowdstrike"]
        self.base_url = cs_cfg["base_url"].rstrip("/")
        self.client_id = cs_cfg["client_id"]
        self.client_secret = cs_cfg["client_secret"]
        self._token = None

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        """Fetch a short-lived OAuth2 bearer token from CrowdStrike."""
        resp = requests.post(
            f"{self.base_url}/oauth2/token",
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _headers(self) -> dict:
        if not self._token:
            self._token = self._get_token()
        return {"Authorization": f"Bearer {self._token}"}

    # ------------------------------------------------------------------
    # Required interface methods
    # ------------------------------------------------------------------

    def isolate_host(self, host_id: str) -> dict:
        """
        Calls the CrowdStrike Network Containment API to isolate the host.
        Endpoint: POST /devices/entities/devices-actions/v2?action_name=contain
        """
        url = f"{self.base_url}/devices/entities/devices-actions/v2"
        payload = {
            "action_parameters": [],
            "ids": [host_id],
        }
        try:
            resp = requests.post(
                url,
                params={"action_name": "contain"},
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return {
                "success": True,
                "message": f"Host {host_id} isolated via CrowdStrike.",
                "raw_response": resp.json(),
            }
        except requests.HTTPError as e:
            return {
                "success": False,
                "message": f"CrowdStrike isolation failed: {e}",
                "raw_response": getattr(e.response, "json", lambda: {})(),
            }

    def get_host_info(self, host_id: str) -> dict:
        """
        Fetches device details from the Hosts API.
        Endpoint: GET /devices/entities/devices/v2
        """
        url = f"{self.base_url}/devices/entities/devices/v2"
        try:
            resp = requests.get(
                url,
                params={"ids": host_id},
                headers=self._headers(),
            )
            resp.raise_for_status()
            resources = resp.json().get("resources", [])
            if not resources:
                return {"hostname": host_id, "ip_address": "unknown", "os": "unknown", "last_seen": "unknown"}
            d = resources[0]
            return {
                "hostname": d.get("hostname", host_id),
                "ip_address": d.get("local_ip", "unknown"),
                "os": d.get("os_version", "unknown"),
                "last_seen": d.get("last_seen", "unknown"),
            }
        except Exception as e:
            return {"hostname": host_id, "ip_address": "unknown", "os": "unknown", "last_seen": str(e)}

    # ------------------------------------------------------------------
    # Optional response actions
    # ------------------------------------------------------------------

    def kill_process(self, host_id: str, process_id: str) -> dict:
        """
        Kills a process via a Real Time Response (RTR) active-responder
        session command. Requires an RTR session to be initialized first.
        NOTE: not live-tested — verify session-init flow against current
        Falcon RTR API docs before relying on this in production.
        """
        try:
            init_resp = requests.post(
                f"{self.base_url}/real-time-response/entities/sessions/v1",
                json={"device_id": host_id},
                headers=self._headers(),
            )
            init_resp.raise_for_status()
            session_id = init_resp.json()["resources"][0]["session_id"]

            cmd_resp = requests.post(
                f"{self.base_url}/real-time-response/entities/active-responder-command/v1",
                json={
                    "base_command": "kill",
                    "command_string": f"kill {process_id}",
                    "session_id": session_id,
                },
                headers=self._headers(),
            )
            cmd_resp.raise_for_status()
            return {
                "success": True,
                "message": f"Kill command sent for process {process_id} on {host_id} via CrowdStrike RTR.",
                "raw_response": cmd_resp.json() if cmd_resp.content else {},
            }
        except Exception as e:
            return {"success": False, "message": f"CrowdStrike kill_process failed: {e}", "raw_response": {}}

    def block_hash(self, file_hash: str) -> dict:
        """
        Adds a custom IOC (indicator of compromise) to block the given hash
        org-wide via the Falcon IOC management API.
        """
        url = f"{self.base_url}/iocs/entities/indicators/v1"
        payload = {
            "indicators": [
                {
                    "type": "sha256" if len(file_hash) == 64 else "md5",
                    "value": file_hash,
                    "action": "prevent",
                    "platforms": ["windows", "mac", "linux"],
                    "description": "Blocked via Containment Agent",
                }
            ]
        }
        try:
            resp = requests.post(url, json=payload, headers=self._headers())
            resp.raise_for_status()
            return {
                "success": True,
                "message": f"Hash {file_hash} added to CrowdStrike IOC block list.",
                "raw_response": resp.json() if resp.content else {},
            }
        except requests.HTTPError as e:
            return {
                "success": False,
                "message": f"CrowdStrike block_hash failed: {e}",
                "raw_response": getattr(e.response, "json", lambda: {})(),
            }

    # quarantine_file: CrowdStrike Falcon has no direct file-quarantine action
    # analogous to Defender's — falls back to BaseConnector's "not supported".

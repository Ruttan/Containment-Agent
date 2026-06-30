"""
Tanium connector.
Uses the Tanium REST API to isolate endpoints via Threat Response.

Required config fields:
  platforms.tanium.api_token
  platforms.tanium.base_url
"""

import requests
from .base import BaseConnector


class TaniumConnector(BaseConnector):

    def __init__(self, config: dict):
        tan_cfg = config["platforms"]["tanium"]
        self.base_url = tan_cfg["base_url"].rstrip("/")
        self.api_token = tan_cfg["api_token"]

    def _headers(self) -> dict:
        return {
            "session": self.api_token,
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Required interface methods
    # ------------------------------------------------------------------

    def isolate_host(self, host_id: str) -> dict:
        """
        Issues a Threat Response isolation action against the host.
        Endpoint: POST /api/v2/threat-response/actions/isolate
        """
        url = f"{self.base_url}/api/v2/threat-response/actions/isolate"
        payload = {"computer_id": host_id}
        try:
            resp = requests.post(url, json=payload, headers=self._headers(), verify=False)
            resp.raise_for_status()
            return {
                "success": True,
                "message": f"Host {host_id} isolated via Tanium.",
                "raw_response": resp.json(),
            }
        except requests.HTTPError as e:
            return {
                "success": False,
                "message": f"Tanium isolation failed: {e}",
                "raw_response": getattr(e.response, "json", lambda: {})(),
            }

    def get_host_info(self, host_id: str) -> dict:
        """
        Fetches endpoint details from the Tanium Endpoint API.
        """
        url = f"{self.base_url}/api/v2/endpoints/{host_id}"
        try:
            resp = requests.get(url, headers=self._headers(), verify=False)
            resp.raise_for_status()
            d = resp.json().get("data", {})
            return {
                "hostname": d.get("name", host_id),
                "ip_address": d.get("ipAddresses", ["unknown"])[0],
                "os": d.get("os", {}).get("name", "unknown"),
                "last_seen": d.get("lastRegistration", "unknown"),
            }
        except Exception as e:
            return {"hostname": host_id, "ip_address": "unknown", "os": "unknown", "last_seen": str(e)}

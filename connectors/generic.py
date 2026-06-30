"""
Generic connector — for any platform not directly supported.
The agent POSTs to the configured isolation_endpoint with a standard payload.

Required config fields:
  platforms.generic.isolation_endpoint
  platforms.generic.api_key
  platforms.generic.api_key_header
"""

import requests
from .base import BaseConnector


class GenericConnector(BaseConnector):

    def __init__(self, config: dict):
        g_cfg = config["platforms"]["generic"]
        self.endpoint = g_cfg["isolation_endpoint"]
        self.api_key = g_cfg["api_key"]
        self.api_key_header = g_cfg.get("api_key_header", "Authorization")

    def _headers(self) -> dict:
        return {
            self.api_key_header: self.api_key,
            "Content-Type": "application/json",
        }

    def isolate_host(self, host_id: str) -> dict:
        payload = {"host_id": host_id, "action": "isolate"}
        try:
            resp = requests.post(self.endpoint, json=payload, headers=self._headers())
            resp.raise_for_status()
            return {
                "success": True,
                "message": f"Host {host_id} isolation request sent.",
                "raw_response": resp.json() if resp.content else {},
            }
        except requests.HTTPError as e:
            return {
                "success": False,
                "message": f"Generic connector isolation failed: {e}",
                "raw_response": {},
            }

    def get_host_info(self, host_id: str) -> dict:
        # Generic connector doesn't know how to fetch host info.
        # Returns minimal placeholder so the rest of the agent still works.
        return {
            "hostname": host_id,
            "ip_address": "unknown",
            "os": "unknown",
            "last_seen": "unknown",
        }

"""
Microsoft Defender connector — Microsoft Graph Security API.

Covers alerts/actions from both Microsoft Defender for Endpoint (MDE) and the
unified Microsoft 365 Defender surface, since both are consolidated under the
Graph Security API (`/security/...`) rather than the older, separate
`api.securitycenter.microsoft.com` MDE API.

Required config fields:
  platforms.defender.tenant_id
  platforms.defender.client_id
  platforms.defender.client_secret

NOTE ON API ENDPOINTS: Like the Tanium and CrowdStrike connectors in this
project, this connector has NOT been live-tested against a real tenant.
Microsoft has been migrating machine-action endpoints from the legacy MDE API
into Graph over the past couple of years, and exact route names/API versions
can shift between v1.0 and beta. Before going live, verify each endpoint
below against the current Microsoft Graph Security API docs
(https://learn.microsoft.com/graph/api/resources/security-api-overview) and
adjust as needed — the auth flow (OAuth2 client credentials) and overall
shape will not change even if a specific path does.

App registration requirements (Azure AD):
  - API permissions (Application, admin-consented): Machine.Isolate,
    Machine.Read.All, Machine.CollectForensics (or the newer Graph
    equivalents under "SecurityEvents"/"SecurityAlert" and
    "MachineAction" scopes depending on which surface you're hitting).
"""

import requests
from .base import BaseConnector


GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class DefenderConnector(BaseConnector):

    def __init__(self, config: dict):
        d_cfg = config["platforms"]["defender"]
        self.tenant_id = d_cfg["tenant_id"]
        self.client_id = d_cfg["client_id"]
        self.client_secret = d_cfg["client_secret"]
        self._token = None

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        """Fetch an OAuth2 client-credentials bearer token scoped to Graph."""
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        resp = requests.post(
            url,
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _headers(self) -> dict:
        if not self._token:
            self._token = self._get_token()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Required interface methods
    # ------------------------------------------------------------------

    def isolate_host(self, host_id: str) -> dict:
        """
        Isolates a machine from the network, restricting it to Defender
        communication only. host_id is the Defender machine ID (deviceId).
        """
        url = f"{GRAPH_BASE}/security/microsoft.graph.security.machines/{host_id}/isolate"
        payload = {
            "comment": "Isolated automatically by Containment Agent following analyst approval.",
            "isolationType": "Full",
        }
        try:
            resp = requests.post(url, json=payload, headers=self._headers())
            resp.raise_for_status()
            return {
                "success": True,
                "message": f"Host {host_id} isolation requested via Microsoft Defender.",
                "raw_response": resp.json() if resp.content else {},
            }
        except requests.HTTPError as e:
            return {
                "success": False,
                "message": f"Defender isolation failed: {e}",
                "raw_response": getattr(e.response, "json", lambda: {})(),
            }

    def get_host_info(self, host_id: str) -> dict:
        """Fetches machine details for display in the approval notification."""
        url = f"{GRAPH_BASE}/security/microsoft.graph.security.machines/{host_id}"
        try:
            resp = requests.get(url, headers=self._headers())
            resp.raise_for_status()
            d = resp.json()
            return {
                "hostname": d.get("computerDnsName", host_id),
                "ip_address": d.get("lastIpAddress", "unknown"),
                "os": d.get("osPlatform", "unknown"),
                "last_seen": d.get("lastSeen", "unknown"),
            }
        except Exception as e:
            return {"hostname": host_id, "ip_address": "unknown", "os": "unknown", "last_seen": str(e)}

    # ------------------------------------------------------------------
    # Optional response actions
    # ------------------------------------------------------------------

    def kill_process(self, host_id: str, process_id: str) -> dict:
        """
        Terminates a running process on the machine via a live-response
        command action.
        """
        url = f"{GRAPH_BASE}/security/microsoft.graph.security.machines/{host_id}/stopAndQuarantineFile"
        payload = {"processId": process_id, "comment": "Terminated via Containment Agent."}
        try:
            resp = requests.post(url, json=payload, headers=self._headers())
            resp.raise_for_status()
            return {
                "success": True,
                "message": f"Process {process_id} termination requested on {host_id}.",
                "raw_response": resp.json() if resp.content else {},
            }
        except requests.HTTPError as e:
            return {
                "success": False,
                "message": f"Defender kill_process failed: {e}",
                "raw_response": getattr(e.response, "json", lambda: {})(),
            }

    def quarantine_file(self, host_id: str, file_path: str = None, file_hash: str = None) -> dict:
        """Quarantines a specific file on the machine, identified by its SHA1 hash."""
        url = f"{GRAPH_BASE}/security/microsoft.graph.security.machines/{host_id}/stopAndQuarantineFile"
        payload = {
            "sha1": file_hash,
            "comment": f"Quarantined via Containment Agent (path: {file_path or 'unknown'}).",
        }
        try:
            resp = requests.post(url, json=payload, headers=self._headers())
            resp.raise_for_status()
            return {
                "success": True,
                "message": f"File quarantine requested on {host_id} (hash: {file_hash}).",
                "raw_response": resp.json() if resp.content else {},
            }
        except requests.HTTPError as e:
            return {
                "success": False,
                "message": f"Defender quarantine_file failed: {e}",
                "raw_response": getattr(e.response, "json", lambda: {})(),
            }

    def block_hash(self, file_hash: str) -> dict:
        """
        Adds an org-wide file indicator (block + alert) for the given SHA256
        hash via the Graph threat-intelligence indicators API.
        """
        url = f"{GRAPH_BASE}/security/tiIndicators"
        payload = {
            "indicatorValue": file_hash,
            "indicatorType": "fileSha256",
            "action": "block",
            "title": "Blocked via Containment Agent",
            "description": "Automatically blocked following analyst-approved containment action.",
            "targetProduct": "Microsoft Defender ATP",
        }
        try:
            resp = requests.post(url, json=payload, headers=self._headers())
            resp.raise_for_status()
            return {
                "success": True,
                "message": f"Hash {file_hash} added to Defender block list.",
                "raw_response": resp.json() if resp.content else {},
            }
        except requests.HTTPError as e:
            return {
                "success": False,
                "message": f"Defender block_hash failed: {e}",
                "raw_response": getattr(e.response, "json", lambda: {})(),
            }

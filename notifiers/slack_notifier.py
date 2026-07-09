"""
Slack Notifier.
Sends the approval request to a Slack channel via an Incoming Webhook.

No Slack app setup required beyond creating a webhook URL.
Instructions: https://api.slack.com/messaging/webhooks
"""

import requests


class SlackNotifier:

    ACTION_LINK_LABELS = {
        "isolate": ":white_check_mark: ISOLATE HOST",
        "kill_process": ":octagonal_sign: KILL PROCESS",
        "quarantine_file": ":file_folder: QUARANTINE FILE",
        "block_hash": ":no_entry_sign: BLOCK HASH",
    }

    def __init__(self, config: dict):
        self.webhook_url = config["notifications"]["slack"]["webhook_url"]

    def send_approval_request(
        self,
        token: str,
        evaluation: dict,
        host_info: dict,
        public_url: str,
    ) -> bool:
        """
        Sends a formatted Slack message with one link per available response
        action plus a Deny link. Returns True if the message was sent successfully.
        """
        deny_url = f"{public_url}/deny/{token}"

        severity = evaluation.get("severity", "unknown").upper()
        severity_emoji = {
            "CRITICAL": ":rotating_light:",
            "HIGH": ":red_circle:",
            "MEDIUM": ":large_yellow_circle:",
            "LOW": ":large_blue_circle:",
        }.get(severity, ":white_circle:")

        fields = [
            {"type": "mrkdwn", "text": f"*Host:*\n{host_info.get('hostname', 'Unknown')}"},
            {"type": "mrkdwn", "text": f"*IP Address:*\n{host_info.get('ip_address', 'Unknown')}"},
            {"type": "mrkdwn", "text": f"*OS:*\n{host_info.get('os', 'Unknown')}"},
            {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
            {"type": "mrkdwn", "text": f"*Threat:*\n{evaluation.get('threat_name', 'Unknown')}"},
            {"type": "mrkdwn", "text": f"*AI Confidence:*\n{evaluation.get('confidence', 'Unknown').upper()}"},
        ]
        mitre = evaluation.get("mitre_technique")
        if mitre:
            fields.append({"type": "mrkdwn", "text": f"*MITRE ATT&CK:*\n{mitre}"})

        available_actions = evaluation.get("available_actions") or ["isolate"]
        action_links = "     ".join(
            f"*<{public_url}/approve/{token}/{action}|{self.ACTION_LINK_LABELS.get(action, action.upper())}>*"
            for action in available_actions
        )

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{severity_emoji} Containment Approval Required"},
            },
            {"type": "section", "fields": fields},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{evaluation.get('summary', 'No summary available.')}"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Why this alerted:*\n{evaluation.get('explanation', 'No detailed explanation available.')}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Suggested fix:*\n{evaluation.get('suggested_fix', 'No specific remediation suggested.')}",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{action_links}     *<{deny_url}|:x: DENY / NO ACTION>*\n_This request expires in 30 minutes._",
                },
            },
        ]

        resp = requests.post(self.webhook_url, json={"blocks": blocks})
        return resp.status_code == 200

    def send_result(self, host_info: dict, action: str, result: dict = None, actor: str = "analyst") -> bool:
        """
        Sends a follow-up message after an action is taken (approved, denied, or expired).
        """
        hostname = host_info.get("hostname", "Unknown")
        action_labels = {
            "isolate": "Host Isolated",
            "kill_process": "Process Terminated",
            "quarantine_file": "File Quarantined",
            "block_hash": "Hash Blocked",
        }
        label = action_labels.get(action, action)
        detail = f" ({result.get('message')})" if result else ""

        if action == "denied":
            text = f":no_entry: *Containment Denied* — `{hostname}` request was denied by {actor}. No action taken."
        elif action == "expired":
            text = f":warning: *Action Expired* — approval request for `{hostname}` expired with no response."
        elif result and not result.get("success"):
            text = f":warning: *{label} FAILED* — `{hostname}`:{detail}"
        else:
            text = f":white_check_mark: *{label}* — `{hostname}`. Approved by {actor}.{detail}"

        resp = requests.post(self.webhook_url, json={"text": text})
        return resp.status_code == 200

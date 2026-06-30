"""
Slack Notifier.
Sends the approval request to a Slack channel via an Incoming Webhook.

No Slack app setup required beyond creating a webhook URL.
Instructions: https://api.slack.com/messaging/webhooks
"""

import requests


class SlackNotifier:

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
        Sends a formatted Slack message with Approve and Deny links.
        Returns True if the message was sent successfully.
        """
        approve_url = f"{public_url}/approve/{token}"
        deny_url = f"{public_url}/deny/{token}"

        severity = evaluation.get("severity", "unknown").upper()
        severity_emoji = {
            "CRITICAL": ":rotating_light:",
            "HIGH": ":red_circle:",
            "MEDIUM": ":large_yellow_circle:",
            "LOW": ":large_blue_circle:",
        }.get(severity, ":white_circle:")

        message = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{severity_emoji} Host Isolation Approval Required",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Host:*\n{host_info.get('hostname', 'Unknown')}"},
                        {"type": "mrkdwn", "text": f"*IP Address:*\n{host_info.get('ip_address', 'Unknown')}"},
                        {"type": "mrkdwn", "text": f"*OS:*\n{host_info.get('os', 'Unknown')}"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                        {"type": "mrkdwn", "text": f"*Threat:*\n{evaluation.get('threat_name', 'Unknown')}"},
                        {"type": "mrkdwn", "text": f"*AI Confidence:*\n{evaluation.get('confidence', 'Unknown').upper()}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*AI Assessment:*\n{evaluation.get('summary', 'No summary available.')}",
                    },
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*<{approve_url}|✅ APPROVE ISOLATION>*     *<{deny_url}|❌ DENY>*\n_This request expires in 30 minutes._",
                    },
                },
            ]
        }

        resp = requests.post(self.webhook_url, json=message)
        return resp.status_code == 200

    def send_result(self, host_info: dict, action: str, actor: str = "analyst") -> bool:
        """
        Sends a follow-up message after an action is taken (approved or denied).
        """
        hostname = host_info.get("hostname", "Unknown")
        if action == "isolated":
            text = f":white_check_mark: *Host Isolated* — `{hostname}` has been isolated from the network. Approved by {actor}."
        elif action == "denied":
            text = f":no_entry: *Isolation Denied* — `{hostname}` isolation was denied by {actor}. No action taken."
        else:
            text = f":warning: *Action Expired* — approval request for `{hostname}` expired with no response."

        resp = requests.post(self.webhook_url, json={"text": text})
        return resp.status_code == 200

"""
Email Notifier.
Sends the approval request as an HTML email with Approve and Deny buttons.

Works with any SMTP server. For Gmail, use an App Password.
Instructions: myaccount.google.com/apppasswords
"""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class EmailNotifier:

    def __init__(self, config: dict):
        email_cfg = config["notifications"]["email"]
        self.smtp_host = email_cfg["smtp_host"]
        self.smtp_port = email_cfg["smtp_port"]
        self.username = email_cfg["username"]
        self.password = email_cfg["password"]
        self.from_address = email_cfg["from_address"]
        self.to_addresses = email_cfg["to_addresses"]

    def _send(self, subject: str, html_body: str) -> bool:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_address
        msg["To"] = ", ".join(self.to_addresses)
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.from_address, self.to_addresses, msg.as_string())
            return True
        except Exception as e:
            print(f"[Email] Failed to send: {e}")
            return False

    ACTION_BUTTON_LABELS = {
        "isolate": "✅ ISOLATE HOST",
        "kill_process": "🛑 KILL PROCESS",
        "quarantine_file": "🗂 QUARANTINE FILE",
        "block_hash": "🚫 BLOCK HASH",
    }
    ACTION_BUTTON_COLORS = {
        "isolate": "#27ae60",
        "kill_process": "#e67e22",
        "quarantine_file": "#8e44ad",
        "block_hash": "#2c3e50",
    }

    def send_approval_request(
        self,
        token: str,
        evaluation: dict,
        host_info: dict,
        public_url: str,
    ) -> bool:
        deny_url = f"{public_url}/deny/{token}"

        severity = evaluation.get("severity", "unknown").upper()
        severity_colors = {
            "CRITICAL": "#c0392b",
            "HIGH": "#e74c3c",
            "MEDIUM": "#e67e22",
            "LOW": "#3498db",
        }
        color = severity_colors.get(severity, "#95a5a6")

        subject = f"[{severity}] Containment Approval Required — {host_info.get('hostname', 'Unknown')}"

        available_actions = evaluation.get("available_actions") or ["isolate"]
        buttons_html = ""
        for action in available_actions:
            label = self.ACTION_BUTTON_LABELS.get(action, action.upper())
            btn_color = self.ACTION_BUTTON_COLORS.get(action, "#27ae60")
            action_url = f"{public_url}/approve/{token}/{action}"
            buttons_html += f"""
              <a href="{action_url}"
                 style="background:{btn_color};color:white;padding:14px 24px;text-decoration:none;
                        border-radius:4px;font-size:15px;font-weight:bold;margin:4px;display:inline-block;">
                {label}
              </a>
            """

        mitre = evaluation.get("mitre_technique")
        mitre_row = ""
        if mitre:
            mitre_row = f"""
              <tr style="background:#f9f9f9;">
                <td style="padding:8px; font-weight:bold;">MITRE ATT&CK</td>
                <td style="padding:8px;">{mitre}</td>
              </tr>
            """

        html = f"""
        <html><body style="font-family: Arial, sans-serif; max-width: 640px; margin: auto;">
          <div style="background:{color}; color:white; padding:16px; border-radius:4px 4px 0 0;">
            <h2 style="margin:0;">Containment Approval Required</h2>
            <p style="margin:4px 0 0;">Severity: {severity}</p>
          </div>
          <div style="border:1px solid #ddd; border-top:none; padding:20px; border-radius:0 0 4px 4px;">
            <table style="width:100%; border-collapse:collapse; margin-bottom:16px;">
              <tr>
                <td style="padding:8px; font-weight:bold; width:140px;">Host</td>
                <td style="padding:8px;">{host_info.get('hostname', 'Unknown')}</td>
              </tr>
              <tr style="background:#f9f9f9;">
                <td style="padding:8px; font-weight:bold;">IP Address</td>
                <td style="padding:8px;">{host_info.get('ip_address', 'Unknown')}</td>
              </tr>
              <tr>
                <td style="padding:8px; font-weight:bold;">OS</td>
                <td style="padding:8px;">{host_info.get('os', 'Unknown')}</td>
              </tr>
              <tr style="background:#f9f9f9;">
                <td style="padding:8px; font-weight:bold;">Threat</td>
                <td style="padding:8px;">{evaluation.get('threat_name', 'Unknown')}</td>
              </tr>
              {mitre_row}
              <tr>
                <td style="padding:8px; font-weight:bold;">AI Confidence</td>
                <td style="padding:8px;">{evaluation.get('confidence', 'Unknown').upper()}</td>
              </tr>
            </table>
            <div style="background:#f0f4f8; padding:16px; border-radius:4px; margin-bottom:16px;">
              <strong>Summary:</strong><br>
              {evaluation.get('summary', 'No summary available.')}
            </div>
            <div style="background:#fffaf0; border-left:4px solid #e67e22; padding:16px; margin-bottom:16px;">
              <strong>Why this alerted:</strong><br>
              {evaluation.get('explanation', 'No detailed explanation available.')}
            </div>
            <div style="background:#eafaf1; border-left:4px solid #27ae60; padding:16px; margin-bottom:24px;">
              <strong>Suggested fix:</strong><br>
              {evaluation.get('suggested_fix', 'No specific remediation suggested.')}
            </div>
            <div style="text-align:center;">
              {buttons_html}
              <a href="{deny_url}"
                 style="background:#c0392b;color:white;padding:14px 32px;text-decoration:none;
                        border-radius:4px;font-size:15px;font-weight:bold;margin:4px;display:inline-block;">
                ❌ DENY / NO ACTION
              </a>
            </div>
            <p style="color:#999;font-size:12px;text-align:center;margin-top:24px;">
              This approval request expires in 30 minutes.
            </p>
          </div>
        </body></html>
        """
        return self._send(subject, html)

    def send_result(self, host_info: dict, action: str, result: dict = None, actor: str = "analyst") -> bool:
        hostname = host_info.get("hostname", "Unknown")
        action_labels = {
            "isolate": "isolated",
            "kill_process": "process terminated",
            "quarantine_file": "file quarantined",
            "block_hash": "hash blocked",
        }
        label = action_labels.get(action, action)
        detail = f" ({result.get('message')})" if result else ""

        if action == "denied":
            subject = f"[DENIED] Containment request for {hostname} was denied"
            body = f"<p>The containment request for <strong>{hostname}</strong> was denied by {actor}. No action was taken.</p>"
        elif action == "expired":
            subject = f"[EXPIRED] Containment approval for {hostname} expired"
            body = f"<p>The containment approval request for <strong>{hostname}</strong> expired with no response.</p>"
        elif result and not result.get("success"):
            subject = f"[FAILED] {label} on {hostname} failed"
            body = f"<p>Approval was granted to perform <strong>{label}</strong> on <strong>{hostname}</strong>, but it failed:{detail}</p>"
        else:
            subject = f"[{label.upper()}] {hostname}"
            body = f"<p><strong>{hostname}</strong>: {label} — approved by {actor}.{detail}</p>"

        html = f"<html><body style='font-family:Arial,sans-serif;'>{body}</body></html>"
        return self._send(subject, html)

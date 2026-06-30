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

    def send_approval_request(
        self,
        token: str,
        evaluation: dict,
        host_info: dict,
        public_url: str,
    ) -> bool:
        approve_url = f"{public_url}/approve/{token}"
        deny_url = f"{public_url}/deny/{token}"

        severity = evaluation.get("severity", "unknown").upper()
        severity_colors = {
            "CRITICAL": "#c0392b",
            "HIGH": "#e74c3c",
            "MEDIUM": "#e67e22",
            "LOW": "#3498db",
        }
        color = severity_colors.get(severity, "#95a5a6")

        subject = f"[{severity}] Host Isolation Approval Required — {host_info.get('hostname', 'Unknown')}"

        html = f"""
        <html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: auto;">
          <div style="background:{color}; color:white; padding:16px; border-radius:4px 4px 0 0;">
            <h2 style="margin:0;">Host Isolation Approval Required</h2>
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
              <tr>
                <td style="padding:8px; font-weight:bold;">AI Confidence</td>
                <td style="padding:8px;">{evaluation.get('confidence', 'Unknown').upper()}</td>
              </tr>
            </table>
            <div style="background:#f0f4f8; padding:16px; border-radius:4px; margin-bottom:24px;">
              <strong>AI Assessment:</strong><br>
              {evaluation.get('summary', 'No summary available.')}
            </div>
            <div style="text-align:center;">
              <a href="{approve_url}"
                 style="background:#27ae60;color:white;padding:14px 32px;text-decoration:none;
                        border-radius:4px;font-size:16px;font-weight:bold;margin-right:16px;">
                ✅ APPROVE ISOLATION
              </a>
              <a href="{deny_url}"
                 style="background:#c0392b;color:white;padding:14px 32px;text-decoration:none;
                        border-radius:4px;font-size:16px;font-weight:bold;">
                ❌ DENY
              </a>
            </div>
            <p style="color:#999;font-size:12px;text-align:center;margin-top:24px;">
              This approval request expires in 30 minutes.
            </p>
          </div>
        </body></html>
        """
        return self._send(subject, html)

    def send_result(self, host_info: dict, action: str, actor: str = "analyst") -> bool:
        hostname = host_info.get("hostname", "Unknown")
        if action == "isolated":
            subject = f"[ISOLATED] {hostname} has been isolated"
            body = f"<p><strong>{hostname}</strong> was successfully isolated from the network. Approved by {actor}.</p>"
        elif action == "denied":
            subject = f"[DENIED] Isolation of {hostname} was denied"
            body = f"<p>Isolation of <strong>{hostname}</strong> was denied by {actor}. No action was taken.</p>"
        else:
            subject = f"[EXPIRED] Isolation approval for {hostname} expired"
            body = f"<p>The isolation approval request for <strong>{hostname}</strong> expired with no response.</p>"

        html = f"<html><body style='font-family:Arial,sans-serif;'>{body}</body></html>"
        return self._send(subject, html)

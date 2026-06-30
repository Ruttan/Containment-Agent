"""Quick email credential test — run this standalone to verify SMTP works."""
import smtplib
import yaml

with open("config.yaml") as f:
    config = yaml.safe_load(f)

email_cfg = config["notifications"]["email"]

print(f"Testing SMTP connection to {email_cfg['smtp_host']}:{email_cfg['smtp_port']}")
print(f"Username: {email_cfg['username']}")
print(f"Password length: {len(email_cfg['password'])} characters")

try:
    with smtplib.SMTP(email_cfg["smtp_host"], email_cfg["smtp_port"]) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        print("STARTTLS OK")
        server.login(email_cfg["username"], email_cfg["password"])
        print("LOGIN OK — credentials are working!")
except smtplib.SMTPAuthenticationError as e:
    print(f"AUTH FAILED: {e}")
except Exception as e:
    print(f"ERROR: {e}")

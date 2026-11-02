import os
import smtplib
from email.message import EmailMessage


class EmailServiceError(Exception):
    """Raised when the configured SMTP service cannot send an email."""


def send_password_reset_otp(email: str, otp: str) -> None:
    """Send a password-reset OTP through the configured SMTP service."""
    host = os.getenv("SMTP_HOST")
    if not host:
        raise EmailServiceError("Email service is not configured. Add SMTP settings to .env.")

    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_FROM", username)
    if not username or not password or not sender:
        raise EmailServiceError("SMTP_USERNAME, SMTP_PASSWORD, and SMTP_FROM must be configured")

    message = EmailMessage()
    message["Subject"] = "Your password reset OTP"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Your password reset OTP is: {otp}\n\nIt expires in 10 minutes. Do not share it with anyone."
    )

    try:
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(message)
    except smtplib.SMTPAuthenticationError as error:
        raise EmailServiceError(
            "Gmail rejected the login. Use a Gmail App Password, not your normal Gmail password."
        ) from error
    except (OSError, smtplib.SMTPException) as error:
        raise EmailServiceError("Could not send OTP email. Check your SMTP settings.") from error

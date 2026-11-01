"""SMTP and IMAP transport for Secure Hybrid Mail JSON envelopes."""

from __future__ import annotations

import imaplib
import json
import smtplib
import ssl
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import Any

from src.config import MailConfig


SUBJECT_MARKER = "[SECURE-HYBRID-MAIL]"


def build_secure_subject(subject: str) -> str:
    clean = " ".join(str(subject or "Encrypted message").split())[:160]
    return f"{SUBJECT_MARKER} {clean}"


def parse_secure_payload(value: str) -> dict[str, Any]:
    if len(value.encode("utf-8")) > 15 * 1024 * 1024:
        raise ValueError("Secure Hybrid Mail payload is too large.")
    envelope = json.loads(value)
    if (
        not isinstance(envelope, dict)
        or envelope.get("protocol") != "SECURE-HYBRID-MAIL"
        or envelope.get("version") != "1.0"
        or not isinstance(envelope.get("payload"), dict)
    ):
        raise ValueError("Message is not a valid Secure Hybrid Mail envelope.")
    return envelope


def _require_config(config: MailConfig) -> None:
    if not config.is_configured:
        raise ValueError("Gmail is not configured in .env.")


def verify_smtp_connection(config: MailConfig) -> None:
    _require_config(config)
    context = ssl.create_default_context()
    with smtplib.SMTP(config.smtp_server, config.smtp_port, timeout=20) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(config.gmail_user, config.gmail_app_password)


def send_secure_email(
    recipient_email: str,
    subject: str,
    json_payload: str,
    config: MailConfig,
) -> str:
    _require_config(config)
    if "@" not in recipient_email or any(char in recipient_email for char in "\r\n"):
        raise ValueError("Recipient email is invalid.")
    envelope = parse_secure_payload(json_payload)

    message = EmailMessage()
    message["From"] = config.gmail_user
    message["To"] = recipient_email.strip()
    message["Subject"] = build_secure_subject(subject)
    message["X-Secure-Hybrid-Mail"] = "1.0"
    message.set_content(json.dumps(envelope, ensure_ascii=False, indent=2))

    context = ssl.create_default_context()
    with smtplib.SMTP(config.smtp_server, config.smtp_port, timeout=20) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(config.gmail_user, config.gmail_app_password)
        refused = server.send_message(message)
    if refused:
        raise RuntimeError("Gmail refused one or more recipients.")
    return str(message["Message-ID"] or "accepted")


def _extract_text(message: EmailMessage) -> str:
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain" and not part.get_filename():
                return part.get_content()
        raise ValueError("Email does not contain a text payload.")
    return message.get_content()


def fetch_secure_emails(
    config: MailConfig,
    limit: int = 20,
    unread_only: bool = False,
) -> list[dict[str, Any]]:
    _require_config(config)
    query = f'(UNSEEN SUBJECT "{SUBJECT_MARKER}")' if unread_only else f'(SUBJECT "{SUBJECT_MARKER}")'
    results: list[dict[str, Any]] = []

    with imaplib.IMAP4_SSL(
        config.imap_server,
        config.imap_port,
        ssl_context=ssl.create_default_context(),
        timeout=20,
    ) as client:
        client.login(config.gmail_user, config.gmail_app_password)
        status, _ = client.select("INBOX", readonly=True)
        if status != "OK":
            raise RuntimeError("Cannot open the Gmail inbox.")
        status, data = client.search(None, query)
        if status != "OK" or not data:
            return results

        message_ids = data[0].split()[-max(1, min(limit, 50)) :]
        for message_id in reversed(message_ids):
            status, fetched = client.fetch(message_id, "(RFC822)")
            if status != "OK" or not fetched:
                continue
            raw = next(
                (item[1] for item in fetched if isinstance(item, tuple)), None
            )
            if not raw:
                continue
            try:
                message = BytesParser(policy=policy.default).parsebytes(raw)
                envelope = parse_secure_payload(_extract_text(message))
                results.append(
                    {
                        "id": message_id.decode("ascii", errors="ignore"),
                        "subject": str(message.get("Subject", SUBJECT_MARKER)),
                        "from": str(message.get("From", envelope.get("sender", ""))),
                        "date": str(message.get("Date", envelope.get("timestamp", ""))),
                        "envelope": envelope,
                    }
                )
            except (ValueError, json.JSONDecodeError, UnicodeError):
                continue
    return results

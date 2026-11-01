"""Environment-backed application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


@dataclass(frozen=True)
class MailConfig:
    gmail_user: str
    gmail_app_password: str
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    imap_server: str = "imap.gmail.com"
    imap_port: int = 993

    @property
    def is_configured(self) -> bool:
        return bool(self.gmail_user and self.gmail_app_password)

    @classmethod
    def from_mapping(cls, values: Mapping[str, str]) -> "MailConfig":
        return cls(
            gmail_user=values.get("GMAIL_USER", "").strip(),
            gmail_app_password="".join(
                values.get("GMAIL_APP_PASSWORD", "").split()
            ),
            smtp_server=values.get("SMTP_SERVER", values.get("SMTP_HOST", "smtp.gmail.com")),
            smtp_port=int(values.get("SMTP_PORT", "587")),
            imap_server=values.get("IMAP_SERVER", values.get("IMAP_HOST", "imap.gmail.com")),
            imap_port=int(values.get("IMAP_PORT", "993")),
        )


def get_mail_config() -> MailConfig:
    return MailConfig.from_mapping(os.environ)


KEYS_DIR = PROJECT_ROOT / "keys"
CONTACTS_DIR = KEYS_DIR / "contacts"
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
MAX_ENVELOPE_BYTES = 15 * 1024 * 1024

import json

import pytest

from src.config import MailConfig
from src.mail_service import build_secure_subject, parse_secure_payload


def test_mail_config_normalizes_app_password():
    config = MailConfig.from_mapping(
        {
            "GMAIL_USER": "alice@gmail.com",
            "GMAIL_APP_PASSWORD": "abcd efgh ijkl mnop",
            "SMTP_PORT": "587",
            "IMAP_PORT": "993",
        }
    )

    assert config.gmail_app_password == "abcdefghijklmnop"
    assert config.smtp_port == 587
    assert config.imap_port == 993
    assert config.is_configured is True


def test_blank_credentials_are_not_configured():
    config = MailConfig.from_mapping({"GMAIL_USER": "", "GMAIL_APP_PASSWORD": ""})
    assert config.is_configured is False


def test_subject_contains_secure_transport_marker():
    assert build_secure_subject("Bao cao mat") == "[SECURE-HYBRID-MAIL] Bao cao mat"


def test_payload_parser_rejects_other_protocols():
    valid = {"protocol": "SECURE-HYBRID-MAIL", "version": "1.0", "payload": {}}
    assert parse_secure_payload(json.dumps(valid)) == valid

    with pytest.raises(ValueError, match="Secure Hybrid Mail"):
        parse_secure_payload('{"protocol":"OTHER"}')

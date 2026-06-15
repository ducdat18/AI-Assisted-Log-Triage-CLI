"""Tests for PII / secret redaction."""

from __future__ import annotations

from loglens.redact import redact, redact_text


def test_redacts_email():
    result = redact("contact alice@example.com for details")
    assert "alice@example.com" not in result.text
    assert "[REDACTED:EMAIL]" in result.text
    assert result.counts["EMAIL"] == 1


def test_redacts_ipv4():
    result = redact("Connection to 10.0.4.21 refused")
    assert "10.0.4.21" not in result.text
    assert "[REDACTED:IPV4]" in result.text


def test_redacts_bearer_token():
    result = redact("Authorization: Bearer abcdef1234567890token")
    assert "abcdef1234567890token" not in result.text


def test_redacts_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dummysignature123"
    result = redact(f"token={jwt}")
    assert jwt not in result.text
    assert "[REDACTED:JWT]" in result.text


def test_redacts_api_key_assignment():
    result = redact("api_key=sup3rs3cretvalue")
    assert "sup3rs3cretvalue" not in result.text


def test_no_false_positive_on_plain_text():
    text = "Tick budget exceeded on shard seven"
    assert redact_text(text) == text


def test_total_counts_multiple_kinds():
    result = redact("mail bob@x.io from 192.168.0.1 done")
    assert result.total >= 2
    assert result.counts.get("EMAIL") == 1
    assert result.counts.get("IPV4") == 1

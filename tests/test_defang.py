"""Tests for defanging, refanging, and URL deconstruction."""

import pytest
from triage.defang import defang_string, parse_target, refang_string
from triage.models import TargetType


def test_defang_url():
    assert defang_string("http://evil.com/login") == "hxxp://evil[.]com/login"
    assert defang_string("https://evil.com/test.php") == "hxxps://evil[.]com/test[.]php"


def test_defang_domain_and_ip():
    assert defang_string("evil.com") == "evil[.]com"
    assert defang_string("192.168.1.1") == "192[.]168[.]1[.]1"
    assert defang_string("already[.]defanged.com") == "already[.]defanged[.]com"


def test_refang_string():
    assert refang_string("hxxp://evil[.]com") == "http://evil.com"
    assert refang_string("hxxps://phishing(.)xyz/login") == "https://phishing.xyz/login"
    assert refang_string("1[.]1[.]1[.]1") == "1.1.1.1"
    assert refang_string("1[.]1[.]1[.]1[:]8080") == "1.1.1.1:8080"


def test_parse_target_domain():
    meta = parse_target("example.com")
    assert meta.target_type == TargetType.DOMAIN
    assert meta.domain == "example.com"
    assert meta.host == "example.com"
    assert meta.defanged_host == "example[.]com"
    assert meta.subdomain is None


def test_parse_target_subdomain():
    meta = parse_target("login.secure.bank.com")
    assert meta.target_type == TargetType.DOMAIN
    assert meta.domain == "bank.com"
    assert meta.host == "login.secure.bank.com"
    assert meta.subdomain == "login.secure"


def test_parse_target_defanged_url():
    meta = parse_target("hxxps://verify-account[.]xyz/reset?token=123")
    assert meta.target_type == TargetType.URL
    assert meta.scheme == "https"
    assert meta.domain == "verify-account.xyz"
    assert meta.host == "verify-account.xyz"
    assert meta.path == "/reset"
    assert meta.query == "token=123"
    assert meta.defanged_target == "hxxps://verify-account[.]xyz/reset?token=123"


def test_parse_target_ip():
    meta = parse_target("1[.]1[.]1[.]1")
    assert meta.target_type == TargetType.IP
    assert meta.host == "1.1.1.1"
    assert meta.domain == "1.1.1.1"
    assert meta.defanged_host == "1[.]1[.]1[.]1"

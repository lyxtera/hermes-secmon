"""Utility tests."""

from secmon.utils import extract_ips, subnet_24, sanitize_message, is_private_or_loopback


def test_extract_ips():
    text = "Failed from 192.168.1.1 and 2001:db8::1"
    ips = extract_ips(text)
    assert "192.168.1.1" in ips


def test_subnet_24():
    assert subnet_24("1.2.3.4") == "1.2.3.0/24"


def test_sanitize_strips_control():
    assert "\n" not in sanitize_message("hello\nworld")


def test_private_ip():
    assert is_private_or_loopback("10.0.0.1")

"""Botnet detection tests."""

from secmon.botnet import detect_and_block, get_blocked_subnets, _is_whitelisted
from secmon.config import load_config


def test_whitelist_private(cfg):
    assert _is_whitelisted("10.0.0.0/24", cfg)


def test_detect_and_block(cfg, state, mock_commands, tmp_path):
    cfg["general"]["botnet_log_file"] = str(tmp_path / "botnet.log")
    lines = []
    for i in range(5):
        for j in range(25):
            lines.append(f"Failed password from 185.1.2.{i}: invalid")
    mock_commands(["journalctl", "--since", "24 hours ago"], "\n".join(lines))
    mock_commands(["iptables", "-N", "BOTNET"], "")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "Chain INPUT\n")
    mock_commands(["iptables", "-I", "INPUT", "-j", "BOTNET"], "")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    mock_commands(["iptables", "-A", "BOTNET", "-s", "185.1.2.0/24", "-j", "DROP"], "")
    alerts = detect_and_block(state, cfg)
    assert len(alerts) >= 1


def test_skip_whitelisted_subnet(cfg, state, mock_commands):
    cfg["whitelist"]["own_ip"] = "203.0.113.1"
    lines = ["Failed password from 203.0.113.5"] * 600
    mock_commands(["journalctl", "--since", "24 hours ago"], "\n".join(lines))
    mock_commands(["iptables", "-N", "BOTNET"], "")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "BOTNET")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    alerts = detect_and_block(state, cfg)
    assert alerts == []

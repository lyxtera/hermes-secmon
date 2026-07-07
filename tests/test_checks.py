"""Threat check tests."""

from secmon.checks import run_checks
from secmon.checks import fail2ban, brute_force, port_scan, ports, invalid_user, kernel, ssh_session, outbound


def test_fail2ban_new_ban(cfg, state, mock_commands):
    ips = " ".join(f"5.5.5.{i}" for i in range(5))
    mock_commands(["fail2ban-client", "status", "sshd"], f"Currently banned: 5\nBanned IP list: {ips}\n")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    alerts = fail2ban.check(state, cfg)
    assert any(a.severity == "HIGH" for a in alerts)


def test_brute_force_critical(cfg, state, mock_commands):
    lines = "\n".join([f"Failed password for root from 10.0.0.{i}" for i in range(15)])
    mock_commands(["journalctl", "--since", "5 minutes ago"], lines)
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    alerts = brute_force.check(state, cfg)
    assert any(a.severity == "CRITICAL" for a in alerts)


def test_brute_force_nil(cfg, state, mock_commands):
    mock_commands(["journalctl", "--since", "5 minutes ago"], "")
    assert brute_force.check(state, cfg) == []


def test_port_scan(cfg, state, mock_commands):
    mock_commands(["journalctl", "-k", "--since", "1 hour ago"], "martian source from 8.8.8.8\n")
    alerts = port_scan.check(state, cfg)
    assert len(alerts) == 1


def test_listening_port_change(cfg, state, mock_commands):
    state["monitor_state"]["known_ports_output"] = "State\n0.0.0.0:22\n"
    mock_commands(["ss", "-tlnp"], "State\n0.0.0.0:22\n0.0.0.0:4444\n")
    alerts = ports.check(state, cfg)
    assert any("4444" in a.message for a in alerts)


def test_invalid_user(cfg, state, mock_commands):
    lines = []
    for i in range(10):
        lines.append(f"Invalid user user{i} from 3.3.3.{i % 5}")
    mock_commands(["journalctl", "--since", "5 minutes ago"], "\n".join(lines))
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    alerts = invalid_user.check(state, cfg)
    assert len(alerts) >= 1


def test_kernel_errors(cfg, state, mock_commands):
    mock_commands(
        ["journalctl", "-k", "--priority=err", "--since", "24 hours ago"],
        "err1\nerr2\nerr3\nerr4\n",
    )
    alerts = kernel.check(state, cfg)
    assert len(alerts) == 1


def test_unauthorized_ssh(cfg, state, mock_commands):
    mock_commands(["ss", "-tnp", "dport", "=", ":22"], "peer 9.9.9.9:12345\n")
    alerts = ssh_session.check(state, cfg)
    assert any(a.severity == "CRITICAL" for a in alerts)


def test_outbound_suspicious(cfg, state, mock_commands):
    mock_commands(
        ["ss", "-tnp", "state", "established"],
        "0.0.0.0:50000        1.2.3.4:4444      users:((",
    )
    alerts = outbound.check(state, cfg)
    assert len(alerts) == 1


def test_outbound_whitelist_skips_telegram(cfg, state, mock_commands):
    """Connections to whitelisted Telegram CIDR by hermes process should not alert."""
    mock_commands(
        ["ss", "-tnp", "state", "established"],
        "0.0.0.0:50000        149.154.166.110:443   users:((\"hermes\",",
    )
    # Verify default whitelist covers this
    assert any(
        entry.get("cidr") == "149.154.160.0/20" and entry.get("process") == "hermes"
        for entry in cfg["whitelist"].get("outbound_destinations", [])
    )
    alerts = outbound.check(state, cfg)
    assert alerts == [], f"Expected no alerts for whitelisted Telegram connection, got: {alerts}"


def test_outbound_whitelist_still_alerts_other_ips(cfg, state, mock_commands):
    """Whitelist should not suppress alerts for non-whitelisted destinations."""
    mock_commands(
        ["ss", "-tnp", "state", "established"],
        "0.0.0.0:50000        149.154.166.110:443   users:((\"hermes\",\n"
        "0.0.0.0:50001        1.2.3.4:4444         users:((",
    )
    state["monitor_state"]["outbound_connections"] = {
        "1.2.3.4:4444:": "1970-01-01T00:00:00Z",
    }
    alerts = outbound.check(state, cfg)
    assert len(alerts) >= 1


def test_run_checks_isolation(cfg, state, mock_commands):
    mock_commands(["fail2ban-client", "status", "sshd"], "")
    mock_commands(["journalctl", "--since", "5 minutes ago"], "")
    mock_commands(["journalctl", "-k", "--since", "1 hour ago"], "")
    mock_commands(["ss", "-tlnp"], "")
    mock_commands(["journalctl", "--since", "5 minutes ago"], "")
    mock_commands(["journalctl", "-k", "--priority=err", "--since", "24 hours ago"], "")
    mock_commands(["ss", "-tnp", "dport", "=", ":22"], "")
    mock_commands(["ss", "-tnp", "state", "established"], "")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    findings = run_checks(state, cfg)
    assert isinstance(findings, list)

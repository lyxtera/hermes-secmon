"""Threat check tests."""

from secmon.checks import run_checks
from secmon.checks import fail2ban, brute_force, port_scan, ports, invalid_user, kernel, ssh_session, outbound


def test_fail2ban_new_ban(cfg, state, mock_commands):
    mock_commands(["fail2ban-client", "status", "sshd"], "Currently banned: 1\nBanned IP list: 5.5.5.5\n")
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
    mock_commands(["ss", "-tnp", "state", "established"], "1.2.3.4:4444 users:((")
    alerts = outbound.check(state, cfg)
    assert len(alerts) == 1


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

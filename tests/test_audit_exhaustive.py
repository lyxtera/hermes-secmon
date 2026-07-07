"""Exhaustive audit coverage tests."""

import io
from datetime import datetime, timezone
from unittest.mock import mock_open, patch

import pytest

from secmon.audit import auth, compliance, logs, network, threat_intel, process
from secmon.audit import trends
from secmon.audit.base import AuditFinding

PASSWD = "root:x:0:0:root:/root:/bin/bash\nnewuser:x:1000:1000::/home/newuser:/bin/bash\n"
SHADOW = "root:*:1:0:99999:7:::\n"
GROUP = "root:x:0:\nsudo:x:27:admin\n"


def test_auth_exhaustive(cfg, state, mock_commands):
    mock_commands(["sshd", "-T"], "maxauthtries 10\npermitemptypasswords yes\n")
    mock_commands(["journalctl", "--since", "24 hours ago"], "Failed password\n" * 200)

    def open_router(path, *a, **k):
        p = str(path)
        mode = a[0] if a else k.get("mode", "r")
        if p.endswith("passwd"):
            data = PASSWD
        elif p.endswith("shadow"):
            data = SHADOW
        elif p.endswith("group"):
            data = GROUP
        elif "sudoers" in p:
            data = "admin ALL=(ALL) NOPASSWD:ALL\n"
        elif "authorized_keys" in p:
            data = "ssh-rsa KEY\n"
        else:
            raise FileNotFoundError(path)
        if "b" in str(mode):
            import io as _io
            return _io.BytesIO(data.encode())
        return io.StringIO(data)

    with patch("os.path.isfile", return_value=True):
        with patch("glob.glob", return_value=["/etc/sudoers.d/bad", "/root/.ssh/authorized_keys"]):
            with patch("builtins.open", side_effect=open_router):
                findings = auth.run(state, cfg)
    assert len(findings) >= 2


def test_compliance_exhaustive(cfg, state, mock_commands):
    for key in (
        "kernel.kptr_restrict", "kernel.yama.ptrace_scope", "fs.protected_hardlinks",
        "fs.protected_symlinks", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.all.log_martians",
        "net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects", "net.ipv4.icmp_echo_ignore_broadcasts",
        "net.ipv4.tcp_syncookies", "kernel.randomize_va_space", "fs.suid_dumpable",
    ):
        mock_commands(["sysctl", "-n", key], "0")
    mock_commands(["apt", "list", "--upgradable"], "openssh/security 1\n")
    mock_commands(["dpkg", "-l", "unattended-upgrades"], "no packages")
    mock_commands(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], "no")
    mock_commands(["chronyc", "tracking"], "System time : 65.0 seconds slow\n")
    mock_commands(["which", "debsums"], "/usr/bin/debsums")
    mock_commands(["debsums", "-c"], "changed: /usr/bin/openssh\n")
    mock_commands(["openssl", "x509", "-in", "/tmp/cert.pem", "-noout", "-enddate"],
                  "notAfter=Jun 20 00:00:00 2026 GMT\n")

    def isfile(p):
        return str(p).endswith(("login.defs", "sources.list")) or "sources.list.d" in str(p)

    def open_router(path, *a, **k):
        p = str(path)
        if p.endswith("login.defs"):
            return io.StringIO("PASS_MAX_DAYS 999\n")
        if "sources.list" in p:
            return io.StringIO("deb http://evil.example.com/debian/\n")
        raise FileNotFoundError(path)

    with patch("os.path.isfile", side_effect=isfile):
        with patch("os.path.isdir", return_value=True):
            with patch("glob.glob", return_value=["/tmp/cert.pem"]):
                with patch("builtins.open", side_effect=open_router):
                    findings = compliance.run(state, cfg)
    assert len(findings) >= 4


def test_threat_intel_exhaustive(cfg, state, mock_commands, tmp_path, monkeypatch):
    www = str(tmp_path / "www")
    monkeypatch.setattr(threat_intel, "WEB_ROOTS", [www])
    mock_commands(["crontab", "-l"], "")
    mock_commands(["systemctl", "list-unit-files", "--type=service", "--state=enabled"],
                  "evil.service enabled\n")
    mock_commands(["systemctl", "cat", "evil.service"], "ExecStart=/tmp/evil.sh\n")
    mock_commands(["systemctl", "list-unit-files", "--state=masked"], "fail2ban.service masked\n")
    mock_commands(["dpkg", "-S", "/usr/bin/x"], "")
    (tmp_path / "www").mkdir()
    (tmp_path / "www" / "c99.php").write_text("<?php eval(base64_decode('x')); ?>")
    with patch("glob.glob", return_value=["/etc/cron.d/evil"]):
        with patch("os.path.isdir", return_value=True):
            with patch("os.walk", return_value=[(www, [], ["c99.php"])]):
                with patch("os.listdir", return_value=["evil"]):
                    with patch("os.path.isfile", return_value=True):
                        with patch("os.access", return_value=True):
                            with patch("os.path.getmtime", return_value=datetime.now(tz=timezone.utc).timestamp()):
                                findings = threat_intel.run(state, cfg)
    assert any(f.check_id == "webshell" for f in findings)


def test_network_exhaustive(cfg, state, mock_commands):
    mock_commands(["ss", "-tlnp"], "State\n0.0.0.0:22\n")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "Chain INPUT (policy ACCEPT)")
    mock_commands(["iptables", "-L", "-n"], "")
    mock_commands(["ip", "link", "show"], "3: tun0: <POINTOPOINT>\n")
    mock_commands(["ip", "neigh", "show"], "10.0.0.1 lladdr aa:bb:cc:dd:ee:01\n10.0.0.2 lladdr aa:bb:cc:dd:ee:01\n")

    def open_router(path, *a, **k):
        p = str(path)
        if p.endswith("resolv.conf"):
            return io.StringIO("nameserver 1.1.1.1\n")
        if p.endswith("nsswitch.conf"):
            return io.StringIO("hosts: files myhostname\n")
        if p.endswith("hosts"):
            return io.StringIO("1.2.3.4 security.debian.org\n")
        raise FileNotFoundError(path)

    with patch("os.path.isfile", return_value=True):
        with patch("builtins.open", side_effect=open_router):
            findings = network.run(state, cfg)
    assert len(findings) >= 2


def test_logs_exhaustive(cfg, state, mock_commands):
    mock_commands(["journalctl", "--since", "24 hours ago"], "\n".join(f"Invalid user u{i}" for i in range(25)))
    mock_commands(["systemctl", "--failed", "--no-legend"], "bad.service failed\n")
    mock_commands(["journalctl", "--list-boots"], "0\n")
    mock_commands(["journalctl", "--verify"], "FAIL\n")
    mock_commands(["journalctl", "--since", "48 hours ago", "-o", "short-iso"],
                  "2026-06-29T08:00:00 h\n2026-06-29T12:00:00 h\n")
    mock_commands(["systemctl", "is-active", "auditd"], "inactive")
    with patch("os.path.isfile", return_value=False):
        with patch("builtins.open", mock_open(read_data="Storage=volatile\n")):
            findings = logs.run(state, cfg)
    assert len(findings) >= 2


def test_process_bpf_and_mounts(cfg, state, mock_commands, mock_bpf_empty):
    mock_commands(["ps", "-eo", "pid="], "1\n2\n")
    mock_commands(["lsmod"], "rootkit 1 0\n")
    mock_commands(["docker", "ps", "--format", "{{.ID}}"], "")
    mock_commands(["cat", "/proc/mounts"],
                  "tmpfs /var/evil tmpfs rw 0 0\nproc /proc proc rw 0 0\n")
    mock_commands(["sysctl", "-n", "kernel.unprivileged_bpf_disabled"], "0")
    mock_commands(["which", "bpftool"], "/usr/sbin/bpftool")
    mock_commands(["bpftool", "-j", "prog", "show"], '[{"id":42,"name":"tp","type":"tracepoint","tag":"t","map_ids":[],"pids":[]}]')
    mock_commands(["bpftool", "prog", "dump", "xlated", "id", "42"], "xlated\n")
    with patch("os.listdir", return_value=["1", "2"]):
        with patch("os.readlink", side_effect=lambda p: "/tmp/[kworker]" if "1" in p else "/usr/bin/bash"):
            def _mock_open(path, *args, **kwargs):
                if "cmdline" in str(path):
                    return io.BytesIO(b"kworker\x00")
                return io.StringIO("kworker\n")
            with patch("builtins.open", side_effect=_mock_open):
                findings = process.run(state, cfg)
    assert len(findings) >= 2


def test_trends_risk_increase(cfg, state):
    state["last_audit_findings"] = [{"check_id": "old", "severity": "HIGH", "message": "old"}]
    state["last_audit_score"] = 5
    current = [AuditFinding("CRITICAL", 1, "new", "new"), AuditFinding("HIGH", 1, "old", "old")]
    findings = trends.run(state, cfg, current)
    assert any(f.check_id == "risk_increase" for f in findings)

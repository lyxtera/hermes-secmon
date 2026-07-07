"""BPF delta watcher tests."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from secmon.audit.base import AuditFinding
from secmon.bpf.audit import run_bpf_audit
from secmon.bpf.auditd import check_audit_gap
from secmon.bpf.classifier import (
    classify_map,
    classify_program,
    is_systemd_whitelisted,
    score_map,
    score_program,
)
from secmon.bpf.collector import collect_bpf_scan
from secmon.bpf.identity import program_stable_key
from secmon.bpf.models import AttachPoint, BpfMap, BpfProgram, LoaderProvenance, WatchState
from secmon.bpf.watcher import run_bpf_watch
from secmon.bpf.watchlist import ensure_bpf_state, get_watchlist, promote_to_baseline
from secmon.modes.bpf import run_bpf_baseline_promote
from secmon.state import CURRENT_VERSION, run_migrations

FIXTURES = Path(__file__).parent / "fixtures" / "bpf"
XLATED_DUMP = b"deadbeefcafe\n"


def _load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _mock_bpf_base(mock_commands, prog_json: str, map_json: str = "[]", link_json: str = "[]"):
    mock_commands(["which", "bpftool"], "/usr/sbin/bpftool")
    mock_commands(["cat", "/proc/sys/kernel/random/boot_id"], "boot-test\n")
    mock_commands(["bpftool", "-j", "prog", "show"], prog_json)
    mock_commands(["bpftool", "-j", "map", "show"], map_json)
    mock_commands(["bpftool", "-j", "link", "show"], link_json)
    mock_commands(["bpftool", "-j", "cgroup", "show", "/"], "{}")
    mock_commands(["bpftool", "-j", "net", "show"], "{}")
    mock_commands(["auditctl", "-s"], "lost 0\nbacklog 0\n")


def _mock_xlated(mock_commands, prog_id: int, data: bytes = XLATED_DUMP):
    mock_commands(
        ["bpftool", "prog", "dump", "xlated", "id", str(prog_id)],
        data.decode("utf-8", errors="replace"),
    )


def _systemd_loader() -> LoaderProvenance:
    return LoaderProvenance(
        pid=1,
        exe="/usr/lib/systemd/systemd",
        systemd_unit="init.scope",
        cgroup="0::/init.scope",
        dpkg_package="systemd",
    )


def test_stable_key_ignores_id_churn(cfg, mock_commands):
    _mock_bpf_base(mock_commands, _load_fixture("prog_show_id5.json"), _load_fixture("map_show.json"))
    _mock_xlated(mock_commands, 5)
    scan1 = collect_bpf_scan(cfg)
    key1 = scan1.programs[0].stable_key

    _mock_bpf_base(mock_commands, _load_fixture("prog_show_id99.json"), _load_fixture("map_show.json"))
    _mock_xlated(mock_commands, 99)
    scan2 = collect_bpf_scan(cfg)
    key2 = scan2.programs[0].stable_key

    assert key1 == key2
    assert scan1.programs[0].id != scan2.programs[0].id


def test_systemd_whitelist_real_sd_fw(cfg):
    prog = BpfProgram(
        id=1,
        name="sd_fw_ingress",
        prog_type="cgroup_skb",
        tag="deadbeef",
        attach_points=[
            AttachPoint("cgroup_ingress", "cgroup", "/system.slice"),
        ],
        loader=_systemd_loader(),
    )
    assert is_systemd_whitelisted(prog, cfg)


def test_spoofed_sd_fw_not_whitelisted(cfg):
    prog = BpfProgram(
        id=2,
        name="sd_fw_ingress",
        prog_type="cgroup_skb",
        tag="deadbeef",
        attach_points=[
            AttachPoint("cgroup_ingress", "cgroup", "/system.slice"),
        ],
        loader=LoaderProvenance(pid=2000, exe="/tmp/evil", cmdline="/tmp/evil"),
    )
    assert not is_systemd_whitelisted(prog, cfg)
    result = score_program(prog, {}, cfg)
    assert result.risk_score > 0


def test_unknown_low_risk_watchlist(cfg, state, mock_commands):
    prog_json = json.dumps([
        {
            "id": 8,
            "name": "benign_tp",
            "type": "tracing",
            "tag": "11111111",
            "map_ids": [],
            "pids": [],
        }
    ])
    _mock_bpf_base(mock_commands, prog_json)
    _mock_xlated(mock_commands, 8, b"benign-bytecode")
    mock_commands(["sysctl", "-n", "kernel.unprivileged_bpf_disabled"], "1")

    findings = run_bpf_audit(state, cfg)
    assert not any(f.severity in ("HIGH", "CRITICAL") for f in findings)
    wl = get_watchlist(state, "programs")
    assert wl
    assert any(e.get("state") == WatchState.SURVEILLANCE.value for e in wl.values())


def test_kprobe_execve_critical(cfg):
    prog = BpfProgram(
        id=3,
        name="evil_kprobe",
        prog_type="kprobe",
        tag="cafebabe",
        attach_points=[AttachPoint("kprobe", "kprobe", "execve")],
        loader=LoaderProvenance(pid=3000, exe="/usr/bin/bpftool", dpkg_package="bpftool"),
    )
    result = score_program(prog, {}, cfg)
    assert result.risk_score >= 100
    assert result.watch_state == WatchState.ALERT_CRITICAL


def test_ringbuf_high_risk_map(cfg):
    m = BpfMap(id=20, name="events", map_type="ringbuf", key_size=0, value_size=0, max_entries=0, flags=0)
    result = score_map(m, cfg)
    assert result.risk_score >= 30
    prog = BpfProgram(
        id=4,
        name="trace_ring",
        prog_type="tracepoint",
        tag="feedface",
        map_ids=[20],
        attach_points=[],
        loader=LoaderProvenance(exe="/usr/bin/bpftool", dpkg_package="bpftool"),
    )
    combined = score_program(prog, {20: m}, cfg)
    assert combined.risk_score >= 70


def test_prog_array_map_high_risk(cfg):
    m = BpfMap(id=30, name="jump", map_type="prog_array", key_size=4, value_size=4, max_entries=16, flags=0)
    result = score_map(m, cfg)
    assert result.risk_score >= 30


def test_vanished_object(cfg, state, mock_commands):
    _mock_bpf_base(mock_commands, _load_fixture("prog_show_id5.json"), _load_fixture("map_show.json"))
    _mock_xlated(mock_commands, 5)
    run_bpf_audit(state, cfg)
    key = next(iter(get_watchlist(state, "programs")))

    _mock_bpf_base(mock_commands, "[]", "[]")
    run_bpf_audit(state, cfg)
    entry = get_watchlist(state, "programs").get(key)
    assert entry is not None
    assert entry.get("state") == WatchState.VANISHED.value


def test_link_escalation_during_surveillance(cfg, state, mock_commands):
    _mock_bpf_base(mock_commands, _load_fixture("prog_show_id5.json"), _load_fixture("map_show.json"), "[]")
    _mock_xlated(mock_commands, 5)
    run_bpf_audit(state, cfg)

    _mock_bpf_base(
        mock_commands,
        _load_fixture("prog_show_id5.json"),
        _load_fixture("map_show.json"),
        _load_fixture("link_new.json"),
    )
    _mock_xlated(mock_commands, 5)
    findings = run_bpf_watch(state, cfg)
    assert any(f.check_id == "NC-9-bpf-link-updated" for f in findings)


def test_audit_lost_monitoring_gap(cfg, state, mock_commands):
    ensure_bpf_state(state)["last_scan"]["audit_lost"] = 0
    ensure_bpf_state(state)["last_scan"]["audit_backlog"] = 0
    mock_commands(["auditctl", "-s"], "lost 5\nbacklog 1\n")
    gap, detail = check_audit_gap(state)
    assert gap
    assert detail["audit_lost"] == 5


def test_audit_lost_finding(cfg, state, mock_commands):
    ensure_bpf_state(state)["last_scan"]["audit_lost"] = 0
    ensure_bpf_state(state)["last_scan"]["audit_backlog"] = 0
    _mock_bpf_base(mock_commands, "[]")
    mock_commands(["auditctl", "-s"], "lost 3\nbacklog 0\n")
    findings = run_bpf_audit(state, cfg)
    assert any(f.check_id == "NC-9-bpf-monitoring-gap" for f in findings)


def test_baseline_promote_rejects_kprobe(cfg, state):
    ensure_bpf_state(state)
    key = "prog:kprobe:tag:abc:fp"
    get_watchlist(state, "programs")[key] = {
        "stable_key": key,
        "metadata": {"prog_type": "kprobe", "map_ids": []},
        "state": "surveillance",
        "risk_score": 90,
        "first_seen": "t",
        "last_seen": "t",
    }
    rc = run_bpf_baseline_promote(state, cfg, key)
    assert rc == 1


def test_state_migration_v3_to_v4():
    data = {"version": 3, "daily_stats": []}
    migrated = run_migrations(data)
    assert migrated["version"] == CURRENT_VERSION
    assert "bpf" in migrated
    assert migrated["bpf"]["schema_version"] == 1


def test_watcher_idempotent(cfg, state, mock_commands):
    _mock_bpf_base(mock_commands, _load_fixture("prog_show_id5.json"), _load_fixture("map_show.json"))
    _mock_xlated(mock_commands, 5)
    run_bpf_audit(state, cfg)
    f1 = run_bpf_watch(state, cfg)
    f2 = run_bpf_watch(state, cfg)
    assert f1 == []
    assert f2 == []


def test_promote_tracepoint_ok(cfg, state):
    ensure_bpf_state(state)
    key = "prog:tracepoint:abc:hash:fp"
    get_watchlist(state, "programs")[key] = {
        "stable_key": key,
        "metadata": {"prog_type": "tracepoint", "map_ids": []},
        "state": "surveillance",
        "risk_score": 10,
        "first_seen": "t",
        "last_seen": "t",
    }
    ok, _ = promote_to_baseline(state, key)
    assert ok
    assert key in state["bpf"]["baseline"]["programs"]


def test_identity_fallback_without_xlated(cfg):
    from secmon.bpf.identity import program_stable_key

    prog = BpfProgram(
        id=1,
        name="fallback",
        prog_type="tracepoint",
        tag="abc",
        xlated_sha256="",
        attach_points=[AttachPoint("tracepoint", "tp", "sys_enter")],
    )
    key = program_stable_key(prog, {})
    assert "fallback" in key


def test_map_stable_key_and_classify_baseline(cfg, state):
    from secmon.bpf.identity import map_stable_key

    m = BpfMap(id=1, name="m", map_type="hash", key_size=4, value_size=8, max_entries=100, flags=0)
    m.stable_key = map_stable_key(m)
    state["bpf"]["baseline"]["maps"][m.stable_key] = {"promoted_at": "t"}
    result = classify_map(m, cfg, {m.stable_key})
    assert result.watch_state == WatchState.BASELINE_MATCH


def test_bpf_cli_baseline_list(cfg, state, capsys):
    from secmon.modes.bpf import run_bpf_baseline_list

    rc = run_bpf_baseline_list(state, cfg)
    assert rc == 0
    assert "programs" in capsys.readouterr().out


def test_bpf_cli_watchlist_clear(cfg, state):
    from secmon.modes.bpf import run_bpf_watchlist_clear

    assert run_bpf_watchlist_clear(state, cfg, "") == 1
    key = "prog:x"
    get_watchlist(state, "programs")[key] = {
        "stable_key": key,
        "state": "surveillance",
        "risk_score": 1,
        "first_seen": "t",
        "last_seen": "t",
        "metadata": {},
    }
    assert run_bpf_watchlist_clear(state, cfg, key) == 0


def test_bpf_cli_watchlist_list(cfg, state, capsys):
    from secmon.modes.bpf import run_bpf_watchlist_list

    assert run_bpf_watchlist_list(state, cfg) == 0
    assert "programs" in capsys.readouterr().out


def test_main_bpf_watch_flag(cfg, state, mock_commands, mock_bpf_empty, tmp_path, monkeypatch):
    from secmon.__main__ import main

    cfg["general"]["data_dir"] = str(tmp_path / "data")
    monkeypatch.setattr("secmon.__main__.load_config", lambda *a, **k: cfg)
    monkeypatch.setattr("secmon.__main__.load_state", lambda *a, **k: state)
    rc = main(["--bpf-watch"])
    assert rc in (0, 1)


def test_auditd_recent_pids(mock_commands):
    from secmon.bpf.auditd import recent_bpf_syscall_pids

    mock_commands(["ausearch", "-k", "secmon-bpf", "--start", "recent", "-i", "--raw"], "type=SYSCALL pid=4242\n")
    assert 4242 in recent_bpf_syscall_pids()


def test_bpftool_unpriv_check(mock_commands):
    from secmon.bpf.audit import bpftool_unpriv_check

    mock_commands(["sysctl", "-n", "kernel.unprivileged_bpf_disabled"], "0")
    mock_commands(["which", "bpftool"], "/usr/sbin/bpftool")
    mock_commands(["cat", "/proc/sys/kernel/random/boot_id"], "b\n")
    mock_commands(["bpftool", "-j", "prog", "show"], '[{"id":1,"name":"p","type":"tracepoint","tag":"t","map_ids":[]}]')
    mock_commands(["bpftool", "-j", "map", "show"], "[]")
    mock_commands(["bpftool", "-j", "link", "show"], "[]")
    mock_commands(["bpftool", "-j", "cgroup", "show", "/"], "{}")
    mock_commands(["bpftool", "-j", "net", "show"], "{}")
    mock_commands(["bpftool", "prog", "dump", "xlated", "id", "1"], "x\n")
    findings = bpftool_unpriv_check({})
    assert any(f.check_id == "NC-9-unpriv" for f in findings)


def test_sd_devices_whitelist(cfg):
    prog = BpfProgram(
        id=1,
        name="sd_devices",
        prog_type="cgroup_device",
        tag="abc",
        attach_points=[AttachPoint("cgroup_devices", "cgroup", "/system.slice")],
        loader=_systemd_loader(),
    )
    assert is_systemd_whitelisted(prog, cfg)

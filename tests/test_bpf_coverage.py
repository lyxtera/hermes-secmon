"""Additional BPF unit tests for collector and classifier edge cases."""

from __future__ import annotations

import json

from secmon.bpf.classifier import can_promote_program, is_systemd_whitelisted
from secmon.bpf.collector import _attach_from_cgroup_net, _attach_from_links, _normalize_prog_list
from secmon.bpf.models import AttachPoint, BpfLink, BpfProgram, LoaderProvenance
from secmon.bpf.watchlist import clear_watchlist_entry, load_watchlist_entry


def test_normalize_prog_list_variants():
    assert _normalize_prog_list(None) == []
    assert _normalize_prog_list({"id": 1}) == [{"id": 1}]
    assert _normalize_prog_list([{"id": 1}]) == [{"id": 1}]


def test_attach_from_links_and_cgroup():
    links = [
        BpfLink(1, 5, "cgroup", "ingress", "/system.slice", "cgroup"),
    ]
    pts = _attach_from_links(links, 5)
    assert pts[0].attach_type == "ingress"

    cgroup = {"path": "/system.slice", "ingress": [5], "egress": [{"id": 9}]}
    net = {"eth0": {"ingress": [5]}}
    pts2 = _attach_from_cgroup_net(5, cgroup, net)
    assert any(p.target_kind == "cgroup" for p in pts2)
    assert any(p.target_kind == "interface" for p in pts2)


def test_sd_fw_egress_whitelist(cfg):
    prog = BpfProgram(
        id=1,
        name="sd_fw_egress",
        prog_type="cgroup_skb",
        tag="abc",
        attach_points=[AttachPoint("cgroup_egress", "cgroup", "/system.slice")],
        loader=LoaderProvenance(exe="/usr/lib/systemd/systemd", cgroup="/system.slice"),
    )
    assert is_systemd_whitelisted(prog, cfg)


def test_can_promote_prog_array_blocked():
    ok, reason = can_promote_program(
        {"prog_type": "tracepoint", "map_ids": [1]},
        [{"id": 1, "map_type": "prog_array"}],
    )
    assert not ok
    assert "prog_array" in reason


def test_watchlist_helpers(state):
    from secmon.bpf.watchlist import ensure_bpf_state

    ensure_bpf_state(state)
    assert load_watchlist_entry(state, "missing") is None
    assert clear_watchlist_entry(state, "missing") is False

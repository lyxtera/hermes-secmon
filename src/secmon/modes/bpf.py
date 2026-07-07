"""BPF watcher and baseline CLI modes."""

from __future__ import annotations

import json

from secmon.alerts import dispatch, findings_to_alerts
from secmon.audit.base import AuditFinding
from secmon.bpf.classifier import can_promote_program
from secmon.bpf.watchlist import clear_watchlist_entry, ensure_bpf_state, promote_to_baseline
from secmon.bpf.watcher import run_bpf_watch
from secmon.state import save_state


def run_bpf_watch_mode(state: dict, cfg: dict) -> int:
    findings = run_bpf_watch(state, cfg)
    alerts = findings_to_alerts(findings, min_severity="HIGH")
    new = dispatch(alerts, state, cfg, stdout=True)
    save_state(cfg, state)
    return 0 if not new else 1


def run_bpf_baseline_list(state: dict, cfg: dict) -> int:
    _ = cfg
    bpf = ensure_bpf_state(state)
    print(json.dumps(bpf.get("baseline", {}), indent=2, sort_keys=True))
    return 0


def run_bpf_baseline_promote(state: dict, cfg: dict, stable_key: str) -> int:
    bpf = ensure_bpf_state(state)
    kind = "programs"
    entry = bpf.get("watchlist", {}).get("programs", {}).get(stable_key)
    if not entry:
        entry = bpf.get("watchlist", {}).get("maps", {}).get(stable_key)
        kind = "maps"
    if not entry:
        print(f"Error: watchlist entry not found: {stable_key}")
        return 1

    if kind == "programs":
        maps_meta = [
            v.get("metadata", {})
            for v in bpf.get("watchlist", {}).get("maps", {}).values()
        ]
        ok, reason = can_promote_program(entry.get("metadata", {}), maps_meta)
        if not ok:
            print(f"Error: cannot promote: {reason}")
            return 1

    ok, msg = promote_to_baseline(state, stable_key, kind=kind)
    if not ok:
        print(f"Error: {msg}")
        return 1

    finding = AuditFinding(
        "INFO",
        3,
        "NC-9-bpf-baseline-promoted",
        f"BPF baseline promoted: {stable_key}",
        {"stable_key": stable_key, "kind": kind},
    )
    alerts = findings_to_alerts([finding], min_severity="INFO")
    dispatch(alerts, state, cfg, stdout=False)
    save_state(cfg, state)
    print(f"Promoted {stable_key} to baseline ({kind})")
    return 0


def run_bpf_watchlist_list(state: dict, cfg: dict) -> int:
    _ = cfg
    bpf = ensure_bpf_state(state)
    print(json.dumps(bpf.get("watchlist", {}), indent=2, sort_keys=True))
    return 0


def run_bpf_watchlist_clear(state: dict, cfg: dict, stable_key: str) -> int:
    if not stable_key:
        print("Error: --key required for watchlist clear")
        return 1
    if not clear_watchlist_entry(state, stable_key):
        print(f"Error: watchlist entry not found: {stable_key}")
        return 1
    save_state(cfg, state)
    print(f"Cleared watchlist entry: {stable_key}")
    return 0

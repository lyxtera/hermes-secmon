"""BPF state helpers and watchlist management."""

from __future__ import annotations

from typing import Any

from secmon.bpf.classifier import classify_map, classify_program
from secmon.bpf.models import BpfMap, BpfProgram, BpfScanResult, WatchState, WatchlistEntry
from secmon.utils import utcnow_iso


def default_bpf_state() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "baseline": {"programs": {}, "maps": {}, "links": {}},
        "watchlist": {"programs": {}, "maps": {}},
        "last_scan": {
            "time": None,
            "boot_id": None,
            "audit_lost": None,
            "audit_backlog": None,
        },
    }


def ensure_bpf_state(state: dict) -> dict[str, Any]:
    bpf = state.setdefault("bpf", default_bpf_state())
    bpf.setdefault("schema_version", 1)
    bpf.setdefault("baseline", {"programs": {}, "maps": {}, "links": {}})
    bpf.setdefault("watchlist", {"programs": {}, "maps": {}})
    bpf.setdefault("last_scan", {
        "time": None,
        "boot_id": None,
        "audit_lost": None,
        "audit_backlog": None,
    })
    return bpf


def baseline_keys(state: dict, kind: str) -> set[str]:
    bpf = ensure_bpf_state(state)
    return set(bpf.get("baseline", {}).get(kind, {}).keys())


def get_watchlist(state: dict, kind: str) -> dict[str, dict[str, Any]]:
    bpf = ensure_bpf_state(state)
    return bpf.setdefault("watchlist", {}).setdefault(kind, {})


def _entry_from_program(
    prog: BpfProgram,
    classification,
    now: str,
    existing: dict[str, Any] | None,
) -> dict[str, Any]:
    entry = {
        "stable_key": prog.stable_key,
        "current_id": prog.id,
        "state": classification.watch_state.value,
        "risk_score": classification.risk_score,
        "first_seen": existing.get("first_seen", now) if existing else now,
        "last_seen": now,
        "last_alert_state": existing.get("last_alert_state") if existing else None,
        "metadata": prog.to_dict(),
        "history": list(existing.get("history", [])) if existing else [],
        "object_kind": "program",
    }
    if existing and existing.get("state") != entry["state"]:
        entry["history"].append(
            {"at": now, "from": existing.get("state"), "to": entry["state"]}
        )
    return entry


def _entry_from_map(
    m: BpfMap,
    classification,
    now: str,
    existing: dict[str, Any] | None,
) -> dict[str, Any]:
    entry = {
        "stable_key": m.stable_key,
        "current_id": m.id,
        "state": classification.watch_state.value,
        "risk_score": classification.risk_score,
        "first_seen": existing.get("first_seen", now) if existing else now,
        "last_seen": now,
        "last_alert_state": existing.get("last_alert_state") if existing else None,
        "metadata": m.to_dict(),
        "history": list(existing.get("history", [])) if existing else [],
        "object_kind": "map",
    }
    if existing and existing.get("state") != entry["state"]:
        entry["history"].append(
            {"at": now, "from": existing.get("state"), "to": entry["state"]}
        )
    return entry


def update_watchlist_from_scan(
    state: dict,
    scan: BpfScanResult,
    cfg: dict,
) -> tuple[dict[str, dict], dict[str, dict]]:
    """Update watchlist from scan; return (programs, maps) watchlist dicts."""
    bpf = ensure_bpf_state(state)
    now = utcnow_iso()
    prog_wl = get_watchlist(state, "programs")
    map_wl = get_watchlist(state, "maps")
    maps_by_id = {m.id: m for m in scan.maps}
    seen_prog_keys: set[str] = set()
    seen_map_keys: set[str] = set()

    bl_prog = baseline_keys(state, "programs")
    bl_map = baseline_keys(state, "maps")

    for prog in scan.programs:
        seen_prog_keys.add(prog.stable_key)
        classification = classify_program(prog, maps_by_id, cfg, bl_prog)
        if classification.watch_state in (WatchState.IGNORED, WatchState.BASELINE_MATCH):
            prog_wl.pop(prog.stable_key, None)
            continue
        existing = prog_wl.get(prog.stable_key)
        if existing is None:
            for entry in prog_wl.values():
                if entry.get("current_id") == prog.id:
                    existing = entry
                    old_key = entry.get("stable_key")
                    if old_key and old_key != prog.stable_key:
                        prog_wl.pop(old_key, None)
                    break
        prog_wl[prog.stable_key] = _entry_from_program(prog, classification, now, existing)

    for m in scan.maps:
        seen_map_keys.add(m.stable_key)
        classification = classify_map(m, cfg, bl_map)
        if classification.watch_state in (WatchState.IGNORED, WatchState.BASELINE_MATCH):
            map_wl.pop(m.stable_key, None)
            continue
        existing = map_wl.get(m.stable_key)
        map_wl[m.stable_key] = _entry_from_map(m, classification, now, existing)

    for key, entry in list(prog_wl.items()):
        if key not in seen_prog_keys:
            entry["state"] = WatchState.VANISHED.value
            entry["last_seen"] = now
            entry["current_id"] = None

    for key, entry in list(map_wl.items()):
        if key not in seen_map_keys:
            entry["state"] = WatchState.VANISHED.value
            entry["last_seen"] = now
            entry["current_id"] = None

    bpf["last_scan"]["time"] = now
    bpf["last_scan"]["boot_id"] = scan.boot_id
    return prog_wl, map_wl


def promote_to_baseline(state: dict, stable_key: str, kind: str = "programs") -> tuple[bool, str]:
    wl = get_watchlist(state, kind)
    entry = wl.get(stable_key)
    if not entry:
        return False, f"watchlist entry not found: {stable_key}"
    bpf = ensure_bpf_state(state)
    bpf["baseline"].setdefault(kind, {})[stable_key] = {
        "promoted_at": utcnow_iso(),
        "metadata": entry.get("metadata", {}),
    }
    wl.pop(stable_key, None)
    return True, "promoted"


def clear_watchlist_entry(state: dict, stable_key: str, kind: str | None = None) -> bool:
    removed = False
    kinds = [kind] if kind else ["programs", "maps"]
    for k in kinds:
        wl = get_watchlist(state, k)
        if stable_key in wl:
            wl.pop(stable_key)
            removed = True
    return removed


def load_watchlist_entry(state: dict, stable_key: str) -> WatchlistEntry | None:
    for kind in ("programs", "maps"):
        raw = get_watchlist(state, kind).get(stable_key)
        if raw:
            return WatchlistEntry.from_dict(raw)
    return None

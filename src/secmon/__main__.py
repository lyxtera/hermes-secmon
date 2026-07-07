"""CLI entry point."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from secmon.config import load_config
from secmon.state import load_state, save_state
from secmon.modes.tick import run_tick
from secmon.modes.check import run_check
from secmon.modes.record import run_record
from secmon.modes.daily import run_daily
from secmon.modes.detect_botnet import run_detect_botnet
from secmon.modes.status import run_status
from secmon.modes.audit_mode import run_audit_mode
from secmon.modes.bpf import (
    run_bpf_baseline_list,
    run_bpf_baseline_promote,
    run_bpf_watch_mode,
    run_bpf_watchlist_clear,
    run_bpf_watchlist_list,
)


def _setup_logging(cfg: dict, verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(message)s")
    # Structured events go to log file via alerts module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secmon",
        description="Security audit and monitoring for Debian 12 VPS",
    )
    parser.add_argument("--tick", action="store_true", help="Primary cron entry (15 min)")
    parser.add_argument("--check", action="store_true", help="Threat checks + anomalies")
    parser.add_argument("--record", action="store_true", help="Record baseline sample")
    parser.add_argument("--daily", action="store_true", help="Daily security digest")
    parser.add_argument("--detect-botnet", action="store_true", help="Botnet detection + blocking")
    parser.add_argument("--status", action="store_true", help="Show baselines and state")
    parser.add_argument("--audit", action="store_true", help="Full multi-layer audit (JSON)")
    parser.add_argument("--bpf-watch", action="store_true", help="BPF watchlist refresh and escalation")
    parser.add_argument(
        "--bpf-baseline",
        nargs="+",
        metavar="ACTION",
        help="BPF baseline: list | promote (with --key)",
    )
    parser.add_argument(
        "--bpf-watchlist",
        nargs="+",
        metavar="ACTION",
        help="BPF watchlist: list | clear (with --key)",
    )
    parser.add_argument("--key", dest="bpf_key", default=None, help="Stable key for BPF promote/clear")
    parser.add_argument("--config", dest="config_path", default=None, help="Config file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args(argv)

    modes = [
        args.tick,
        args.check,
        args.record,
        args.daily,
        args.detect_botnet,
        args.status,
        args.audit,
        args.bpf_watch,
        bool(args.bpf_baseline),
        bool(args.bpf_watchlist),
    ]
    if sum(bool(m) for m in modes) != 1:
        parser.error(
            "Specify exactly one mode: --tick, --check, --record, --daily, "
            "--detect-botnet, --status, --audit, --bpf-watch, --bpf-baseline, or --bpf-watchlist"
        )

    cfg = load_config(args.config_path)
    _setup_logging(cfg, args.verbose)
    data_dir = cfg["general"]["data_dir"]
    os.makedirs(data_dir, exist_ok=True)

    state = load_state(cfg)

    if args.tick:
        return run_tick(state, cfg)
    if args.check:
        return run_check(state, cfg)
    if args.record:
        return run_record(state, cfg)
    if args.daily:
        return run_daily(state, cfg)
    if args.detect_botnet:
        return run_detect_botnet(state, cfg)
    if args.status:
        return run_status(state, cfg)
    if args.audit:
        return run_audit_mode(state, cfg)
    if args.bpf_watch:
        return run_bpf_watch_mode(state, cfg)
    if args.bpf_baseline:
        action = args.bpf_baseline[0]
        if action == "list":
            return run_bpf_baseline_list(state, cfg)
        if action == "promote":
            if not args.bpf_key:
                parser.error("--key required for --bpf-baseline promote")
            return run_bpf_baseline_promote(state, cfg, args.bpf_key)
        parser.error("Unknown --bpf-baseline action; use list or promote")
    if args.bpf_watchlist:
        action = args.bpf_watchlist[0]
        if action == "list":
            return run_bpf_watchlist_list(state, cfg)
        if action == "clear":
            if not args.bpf_key:
                parser.error("--key required for --bpf-watchlist clear")
            return run_bpf_watchlist_clear(state, cfg, args.bpf_key)
        parser.error("Unknown --bpf-watchlist action; use list or clear")
    return 1


if __name__ == "__main__":
    sys.exit(main())

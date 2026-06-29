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
    ]
    if sum(bool(m) for m in modes) != 1:
        parser.error("Specify exactly one mode: --tick, --check, --record, --daily, "
                       "--detect-botnet, --status, or --audit")

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
    return 1


if __name__ == "__main__":
    sys.exit(main())

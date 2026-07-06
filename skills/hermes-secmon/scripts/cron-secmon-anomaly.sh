#!/usr/bin/env bash
# cron-secmon-anomaly.sh — Hermes cron (no_agent) for anomaly detection
# Runs independently of --tick so anomalies surface immediately.
# Dedicated job = visible, frequent, and separate from routine ticks.
#
# Silent when no anomalies or baselines not yet calibrated (empty stdout).
# Outputs formatted alert when anomaly detected, then exits 0.
set -euo pipefail

cd /opt/secmon

OUTPUT="$(/opt/secmon/venv/bin/python3 -c '
import sys, os, json

# Ensure secmon package is importable
sys.path.insert(0, "/opt/secmon/src")

from secmon.config import load_config
from secmon.metrics import collect_metrics_from_state, invalidate_cache
from secmon.anomaly import detect_anomalies
from secmon.state import load_state

cfg = load_config()
state = load_state(cfg)

# Force fresh metric collection (no cache) for anomaly accuracy
invalidate_cache()
metrics = collect_metrics_from_state(cfg, state)

# detect_anomalies returns list of Alert objects (or empty if baselines not ready)
anomalies = detect_anomalies(metrics, state, cfg)

if not anomalies:
    sys.exit(0)

for a in anomalies:
    sev = getattr(a, "severity", "MEDIUM")
    src = getattr(a, "source", "anomaly")
    msg = getattr(a, "message", str(a))
    print(f"[{sev}] {src}: {msg}")

print(f"\nAnomaly check: {len(anomalies)} metric(s) deviating")
' 2>&1)" && RC=$? || RC=$?

printf '%s' "$OUTPUT"
exit 0
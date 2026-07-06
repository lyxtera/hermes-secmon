#!/usr/bin/env python3
"""Hermes cron script — daily security digest (08:00 UTC).

Sends via Telegram Bot API sendRichMessage with compact structured blocks.
"""
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

from telegramify_markdown import richify

PLUGIN_DIR = os.environ.get(
    "SECMON_PLUGIN_DIR",
    os.path.expanduser("~/.hermes/plugins/secmon")
)

def find_cli() -> str:
    candidates = []
    venv = os.path.join(PLUGIN_DIR, "venv", "bin", "secmon")
    if os.access(venv, os.X_OK):
        candidates.append(venv)
    src = os.environ.get("SECMON_SOURCE", "/opt/secmon")
    src_venv = os.path.join(src, "venv", "bin", "secmon")
    if os.access(src_venv, os.X_OK):
        candidates.append(src_venv)
    candidates.append("/usr/local/bin/secmon")
    for c in candidates:
        if os.access(c, os.X_OK):
            return c
    return candidates[-1]

CLI = find_cli()
CONFIG = os.environ.get("SECMON_CONFIG_PATH", "/etc/secmon/config.yaml")

cmd = [CLI, "--daily"]
if os.path.isfile(CONFIG):
    cmd += ["--config", CONFIG]

proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
raw = proc.stdout.strip()

# Silent — no data
if not raw:
    sys.exit(0)

# Bot token
bot_token = ""
env_path = "/root/.hermes/.env"
if os.path.isfile(env_path):
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("TELEGRAM_BOT_TOKEN="):
                bot_token = line.split("=", 1)[1].strip("\"'")
                break
if not bot_token:
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
if not bot_token:
    print("ERROR: TELEGRAM_BOT_TOKEN not set", file=sys.stderr)
    sys.exit(1)

CHAT_ID = "557337160"
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# Parse daily output — extract metrics table and summary
lines = raw.split("\n")
metrics = []
summary_items = []
in_table = False
in_summary = False
findings_count = "0"

for line in lines:
    s = line.strip()

    # Metrics table
    if s.startswith("|") and "Metric" in s and "Value" in s:
        in_table = True
        continue
    if in_table and s.startswith("|") and ":---" in s:
        continue
    if in_table and s.startswith("|"):
        if "**Summary**" in s or "---" in s:
            in_table = False
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if len(cells) >= 4:
            metric = re.sub(r"\*+", "", cells[0]).strip()
            val = cells[1].strip().replace("`", "")
            bl = cells[2].strip().replace("`", "")
            delta = cells[3].strip()
            metrics.append((metric, val, bl, delta))
        elif len(cells) >= 2:
            metric = re.sub(r"\*+", "", cells[0]).strip()
            val = cells[1].strip().replace("`", "")
            metrics.append((metric, val, "", ""))

    # Summary bullets
    if "**Summary**" in s:
        in_table = False
        in_summary = True
        continue
    if in_summary and s.startswith("•"):
        summary_items.append(s.lstrip("•").strip())
    if "`secmon --audit`" in s:
        in_summary = False

    # Findings count
    if "Findings:" in s:
        findings_count = s.split("`")[1] if "`" in s else "?"

# Build compact markdown
md_parts = [f"# 📅 Secmon Daily Digest\n_{timestamp}_"]

# Metrics table (compact)
if metrics:
    md_parts.append("\n## 📊 24h Activity\n")
    md_parts.append("| Metric | Value | Δ |")
    md_parts.append("| :--- | :---: | :---: |")
    for metric, val, _, delta in metrics:
        md_parts.append(f"| {metric} | `{val}` | {delta} |")
    md_parts.append("")

# Summary
if summary_items:
    md_parts.append("**🔍 Summary**\n")
    for item in summary_items:
        md_parts.append(f"- {item}")

md_parts.append(f"\n`secmon --audit` — Full audit")
md = "\n".join(md_parts)

rich_msg = richify(md, mode="html")
payload = json.dumps({
    "chat_id": CHAT_ID,
    "rich_message": rich_msg.to_dict()
}).encode()

req = urllib.request.Request(
    f"https://api.telegram.org/bot{bot_token}/sendRichMessage",
    data=payload,
    headers={"Content-Type": "application/json"}
)
try:
    resp = urllib.request.urlopen(req, timeout=15)
    result = json.loads(resp.read())
    if not result.get("ok"):
        print(f"FAIL: {result.get('description', '?')}", file=sys.stderr)
        sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
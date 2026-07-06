#!/usr/bin/env python3
"""Hermes cron script — security tick (every 15 min).

Sends findings via Telegram Bot API sendRichMessage with compact
structured blocks. Silent exit when no findings.
"""
import json
import os
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

cmd = [CLI, "--tick"]
if os.path.isfile(CONFIG):
    cmd += ["--config", CONFIG]

proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
raw = proc.stdout.strip()

# Silent — no findings
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

# Parse tick output — look for findings table
# Routine findings to suppress (constant background noise)
ROUTINE_PATTERNS = [
    "invalid_user",
    "username enumeration",
    "invalid users",
    "Invalid User",
    "Username enumeration",
]

def _is_routine(text: str) -> bool:
    lower = text.lower()
    return any(p.lower() in lower for p in ROUTINE_PATTERNS)

lines = raw.split("\n")
findings = []
suppressed = 0
for line in lines:
    s = line.strip()
    if s.startswith("|") and s.endswith("|") and ":---" not in s and "Finding" not in s:
        cells = [c.strip().replace("*", "") for c in s.strip("|").split("|")]
        if len(cells) >= 2:
            finding_text = " · ".join(cell for cell in cells[:3] if cell)
            if _is_routine(finding_text):
                suppressed += 1
                continue
            findings.append(finding_text)

# Build compact markdown
md_parts = [f"## 🔔 Secmon Tick\n_{timestamp}_"]
if findings:
    md_parts.append(f"**{len(findings)} finding(s)**\n")
    for f_item in findings:
        md_parts.append(f"- {f_item}")
    if suppressed:
        md_parts.append(f"\n*({suppressed} routine finding(s) suppressed)*")
elif suppressed:
    # Only routine findings — silenced
    sys.exit(0)
else:
    md_parts.append(f"\n{raw}")

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
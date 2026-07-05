#!/usr/bin/env python3
"""Hermes cron script — deep forensic audit.
Sends directly via Telegram Bot API sendRichMessage (supports tables).
"""
import json
import os
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

# --- Paths ---
PLUGIN_DIR = os.environ.get(
    "SECMON_PLUGIN_DIR",
    os.path.expanduser("~/.hermes/plugins/secmon")
)

# Find the CLI binary
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

# --- Run audit ---
cmd = [CLI, "--audit"]
if os.path.isfile(CONFIG):
    cmd += ["--config", CONFIG]

proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
raw = proc.stdout.strip()

# Silent — no findings
if not raw:
    sys.exit(0)

# --- Get bot token ---
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

# --- Format message ---
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
message = f"*🔍 Secmon Audit* — _{timestamp}_\n\n{raw}"

# --- Send via sendRichMessage ---
payload = json.dumps({
    "chat_id": CHAT_ID,
    "rich_message": {"markdown": message}
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
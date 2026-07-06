#!/usr/bin/env python3
"""Hermes cron script — deep forensic audit with structured rich messages.

Sends via Telegram Bot API sendRichMessage using structured blocks
(section headings, tables, dividers) via the telegramify-markdown library.
"""
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

from telegramify_markdown import richify

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
else:
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")

if not bot_token:
    print("ERROR: TELEGRAM_BOT_TOKEN not set", file=sys.stderr)
    sys.exit(1)

CHAT_ID = "557337160"
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# --- Parse secmon output into severity groupings ---
lines = raw.split("\n")
sections: dict[str, list[tuple[str, str, str, str]]] = {
    "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": [],
}

for line in lines:
    stripped = line.strip()

    # Skip non-table lines
    if not stripped.startswith("|") or not stripped.endswith("|"):
        continue

    # Skip header / separator rows
    if ":---" in stripped or "---" in stripped:
        continue
    if "Finding" in stripped and "Check" in stripped:
        continue

    # Parse finding row: | emoji **finding** | emoji `check_id` | details | action |
    cells = [c.strip() for c in stripped.strip("|").split("|")]
    if len(cells) < 4:
        continue

    finding = cells[0].strip()
    check = cells[1].strip()
    layer = cells[2].strip()
    action = cells[3].strip()

    # Clean up markdown formatting for display
    finding_clean = re.sub(r"\*+", "", finding).strip()
    check_clean = re.sub(r"`", "", check).strip()

    # Determine severity from the finding cell content
    if "🔴" in finding:
        sections["CRITICAL"].append((finding_clean, check_clean, layer, action))
    elif "🟠" in finding or "HIGH" in finding:
        sections["HIGH"].append((finding_clean, check_clean, layer, action))
    elif "🟡" in finding or "MED" in finding:
        sections["MEDIUM"].append((finding_clean, check_clean, layer, action))
    else:
        sections["LOW"].append((finding_clean, check_clean, layer, action))

# Count total findings
total = sum(len(v) for v in sections.values())
if total == 0:
    # No findings — silent exit
    sys.exit(0)

# --- Build structured markdown with sections ---
md_parts: list[str] = [
    f"# 🔍 Secmon Audit\n_{timestamp}_\n\nTotal: **{total}** findings\n\n---"
]

severity_labels = [
    ("CRITICAL", "🔴 CRITICAL"),
    ("HIGH", "🟠 HIGH"),
    ("MEDIUM", "🟡 MEDIUM"),
    ("LOW", "🔵 LOW · ℹ️ INFO"),
]

for sev_key, sev_label in severity_labels:
    rows = sections[sev_key]
    if not rows:
        continue

    md_parts.append(f"\n## {sev_label} — {len(rows)} finding(s)\n")
    md_parts.append("| Finding | Check | Action |")
    md_parts.append("| :--- | :--- | :--- |")
    for finding, check, layer, action in rows:
        md_parts.append(f"| {finding} | {check} | {action} |")
    md_parts.append("\n---")

md_parts.append(f"\n`secmon --audit` — Full forensic audit")

md = "\n".join(md_parts)

# --- Convert to Rich HTML and send ---
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
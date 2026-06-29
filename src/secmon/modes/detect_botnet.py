"""--detect-botnet mode."""

from __future__ import annotations

from secmon.alerts import dispatch
from secmon.botnet import detect_and_block
from secmon.state import save_state


def run_detect_botnet(state: dict, cfg: dict) -> int:
    alerts = detect_and_block(state, cfg)
    new = dispatch(alerts, state, cfg)
    save_state(cfg, state)
    return 0 if not new else 1

"""--audit mode: full multi-layer JSON audit."""

from __future__ import annotations

from secmon.audit import run_audit
from secmon.output import format_audit_json
from secmon.state import save_state


def run_audit_mode(state: dict, cfg: dict) -> int:
    result = run_audit(state, cfg)
    print(format_audit_json(result))
    save_state(cfg, state)
    return 1 if result.get("critical_count", 0) > 0 else 0

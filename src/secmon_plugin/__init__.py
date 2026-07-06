"""Hermes Agent plugin — security audit and monitoring for deployed servers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secmon_plugin import schemas, tools


def register(ctx: Any) -> None:
    """Wire secmon tools, hooks, slash commands, and bundled skills into Hermes."""

    # Register bundled skills — loaded as secmon:<name> via skill_view()
    skills_dir = Path(__file__).parent / "skills"
    if skills_dir.is_dir():
        for child in sorted(skills_dir.iterdir()):
            skill_md = child / "SKILL.md"
            if child.is_dir() and skill_md.exists():
                ctx.register_skill(child.name, skill_md)

    for name, schema, handler, description in tools.TOOL_DEFINITIONS:
        ctx.register_tool(
            name=name,
            toolset="secmon",
            schema=schema,
            handler=handler,
            description=description,
        )

    def on_pre_llm_call(**kwargs: Any) -> dict[str, str] | None:
        del kwargs
        try:
            summary = tools.security_context_summary()
            if summary:
                return {"context": summary}
        except Exception:
            pass
        return None

    ctx.register_hook("pre_llm_call", on_pre_llm_call)

    def secmon_command(args: str, **kwargs: Any) -> str:
        del kwargs
        mode = (args or "status").strip().lower() or "status"
        result = tools.run_mode(mode)
        return json.dumps(result, indent=2)

    ctx.register_command(
        "secmon",
        secmon_command,
        "Run secmon: /secmon [status|check|audit|record|daily|detect-botnet|tick|remediate]",
    )

    def secmon_remediate_command(args: str, **kwargs: Any) -> str:
        del kwargs
        parts = (args or "").strip().split()
        if not parts:
            return json.dumps({"success": False, "error": "Missing action"} , indent=2)
        action = parts[0]
        config_path = parts[1] if len(parts) >= 2 else None
        result = tools.remediate_action(action, config_path)
        return json.dumps(result, indent=2)

    ctx.register_command(
        "secmon_remediate",
        secmon_remediate_command,
        "Apply safe remediation: /secmon_remediate self_protection_fix_permissions [config_path]",
    )

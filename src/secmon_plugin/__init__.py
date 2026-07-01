"""Hermes Agent plugin — security audit and monitoring for deployed servers."""

from __future__ import annotations

import json
from typing import Any

from secmon_plugin import schemas, tools


def register(ctx: Any) -> None:
    """Wire secmon tools, hooks, and slash commands into Hermes."""

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
        "Run secmon: /secmon [status|check|audit|record|daily|detect-botnet|tick]",
    )

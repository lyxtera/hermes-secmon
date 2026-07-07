"""Subprocess helpers — always argument-list form, never shell=True."""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any, Callable

logger = logging.getLogger("secmon.shell")

# Injectable runner for tests
_runner: Callable[..., subprocess.CompletedProcess] | None = None


def set_runner(runner: Callable[..., subprocess.CompletedProcess] | None) -> None:
    global _runner
    _runner = runner


def run_cmd(
    args: list[str],
    *,
    timeout: int = 30,
    text: bool = True,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run external command with argument list only."""
    fn = _runner or subprocess.run
    try:
        return fn(
            args,
            capture_output=True,
            text=text,
            timeout=timeout,
            check=check,
            shell=False,
        )
    except FileNotFoundError:
        # Many integrations are optional; missing binaries should not spam cron stderr.
        logger.debug("command not found: %s", args[0])
        raise
    except subprocess.TimeoutExpired:
        logger.debug("command timed out: %s", " ".join(args))
        raise


def run_cmd_safe(args: list[str], *, timeout: int = 30, default: str = "") -> str:
    """Run command, return stdout or default on failure."""
    try:
        result = run_cmd(args, timeout=timeout)
        if result.returncode != 0:
            logger.debug("command failed rc=%s: %s", result.returncode, " ".join(args))
            return default
        return result.stdout or default
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("command error: %s — %s", " ".join(args), exc)
        return default


def run_cmd_json(args: list[str], *, timeout: int = 30) -> dict[str, Any] | list[Any] | None:
    """Run command and parse JSON stdout, or return None on failure."""
    raw = run_cmd_safe(args, timeout=timeout, default="")
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.debug("invalid JSON from: %s", " ".join(args))
        return None

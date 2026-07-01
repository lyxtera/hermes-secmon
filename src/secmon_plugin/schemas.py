"""JSON tool schemas exposed to the Hermes LLM."""

from __future__ import annotations

from typing import Any

SCHEMAS: dict[str, dict[str, Any]] = {
    "secmon_status": {
        "name": "secmon_status",
        "description": "Show security monitor baselines, state, and current metrics.",
        "parameters": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Optional path to secmon config YAML.",
                }
            },
            "required": [],
        },
    },
    "secmon_check": {
        "name": "secmon_check",
        "description": "Run realtime threat checks and statistical anomaly detection.",
        "parameters": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Optional path to secmon config YAML.",
                }
            },
            "required": [],
        },
    },
    "secmon_audit": {
        "name": "secmon_audit",
        "description": "Run a full multi-layer forensic security audit (JSON report).",
        "parameters": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Optional path to secmon config YAML.",
                }
            },
            "required": [],
        },
    },
    "secmon_record": {
        "name": "secmon_record",
        "description": "Collect metrics and append a baseline calibration sample.",
        "parameters": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Optional path to secmon config YAML.",
                }
            },
            "required": [],
        },
    },
    "secmon_daily": {
        "name": "secmon_daily",
        "description": "Produce a human-readable daily security digest.",
        "parameters": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Optional path to secmon config YAML.",
                }
            },
            "required": [],
        },
    },
    "secmon_detect_botnet": {
        "name": "secmon_detect_botnet",
        "description": "Run botnet /24 subnet analysis and automatic iptables blocking.",
        "parameters": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Optional path to secmon config YAML.",
                }
            },
            "required": [],
        },
    },
}

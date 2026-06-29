"""Deep audit orchestration."""

from __future__ import annotations

import logging
from typing import Any

from secmon.audit.base import AuditFinding
from . import (
    auth,
    compliance,
    file_integrity,
    logs,
    network,
    process,
    threat_intel,
    trends,
)

logger = logging.getLogger("secmon.audit")

LAYERS = [
    ("file_integrity", file_integrity),
    ("network", network),
    ("process", process),
    ("auth", auth),
    ("logs", logs),
    ("threat_intel", threat_intel),
    ("compliance", compliance),
]


def run_audit(state: dict, cfg: dict) -> dict[str, Any]:
    all_findings: list[AuditFinding] = []
    layer_results: dict[str, list] = {}

    for name, module in LAYERS:
        try:
            layer_findings = module.run(state, cfg)
            layer_results[name] = [
                {
                    "severity": f.severity,
                    "score": f.score,
                    "layer": f.layer,
                    "check_id": f.check_id,
                    "message": f.message,
                    "detail": f.detail,
                }
                for f in layer_findings
            ]
            all_findings.extend(layer_findings)
        except Exception as exc:
            logger.error("audit layer %s failed: %s", name, exc)
            layer_results[name] = [{"error": str(exc)}]

    try:
        trend_findings = trends.run(state, cfg, all_findings)
        layer_results["trends"] = [
            {
                "severity": f.severity,
                "score": f.score,
                "layer": f.layer,
                "check_id": f.check_id,
                "message": f.message,
                "detail": f.detail,
            }
            for f in trend_findings
        ]
        all_findings.extend(trend_findings)
    except Exception as exc:
        logger.error("audit trends failed: %s", exc)

    total_score = sum(f.score for f in all_findings if f.layer <= 7)
    critical = [f for f in all_findings if f.severity == "CRITICAL"]
    high = [f for f in all_findings if f.severity == "HIGH"]

    return {
        "total_score": total_score,
        "finding_count": len(all_findings),
        "critical_count": len(critical),
        "high_count": len(high),
        "layers": layer_results,
        "findings": [
            {
                "severity": f.severity,
                "score": f.score,
                "layer": f.layer,
                "check_id": f.check_id,
                "message": f.message,
                "detail": f.detail,
            }
            for f in all_findings
        ],
    }

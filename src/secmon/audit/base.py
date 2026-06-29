"""Audit finding model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_SCORES = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}


@dataclass
class AuditFinding:
    severity: str
    layer: int
    check_id: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def score(self) -> int:
        return SEVERITY_SCORES.get(self.severity, 0)

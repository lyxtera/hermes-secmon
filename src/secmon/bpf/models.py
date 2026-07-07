"""BPF surveillance data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class WatchState(str, Enum):
    IGNORED = "ignored"
    BASELINE_MATCH = "baseline_match"
    SURVEILLANCE = "surveillance"
    BENIGN_CANDIDATE = "benign_candidate"
    VANISHED = "vanished"
    ALERT_HIGH = "alert_high"
    ALERT_CRITICAL = "alert_critical"


@dataclass
class AttachPoint:
    attach_type: str
    target_kind: str
    target: str

    def as_tuple(self) -> tuple[str, str, str]:
        return (self.attach_type, self.target_kind, self.target)


@dataclass
class LoaderProvenance:
    pid: int | None = None
    ppid: int | None = None
    pid_start_time: str | None = None
    exe: str = ""
    exe_sha256: str | None = None
    cmdline: str = ""
    uid: int | None = None
    euid: int | None = None
    auid: int | None = None
    capabilities: str = ""
    systemd_unit: str = ""
    cgroup: str = ""
    namespaces: dict[str, str] = field(default_factory=dict)
    dpkg_package: str = ""
    parent_chain: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BpfMap:
    id: int
    name: str
    map_type: str
    key_size: int
    value_size: int
    max_entries: int
    flags: int
    btf_id: int | None = None
    pinned_paths: list[str] = field(default_factory=list)
    fd_holder_pids: list[int] = field(default_factory=list)
    owner_program_ids: list[int] = field(default_factory=list)
    btf_hash: str = "none"
    stable_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BpfLink:
    link_id: int
    prog_id: int
    link_type: str
    attach_type: str
    target: str
    target_kind: str
    pinned_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BpfProgram:
    id: int
    name: str
    prog_type: str
    tag: str
    uid: int | None = None
    loaded_at: str = ""
    map_ids: list[int] = field(default_factory=list)
    btf_id: int | None = None
    verified_insns: int | None = None
    xlated_sha256: str = ""
    pinned_paths: list[str] = field(default_factory=list)
    fd_holder_pids: list[int] = field(default_factory=list)
    attach_points: list[AttachPoint] = field(default_factory=list)
    links: list[BpfLink] = field(default_factory=list)
    loader: LoaderProvenance = field(default_factory=LoaderProvenance)
    stable_key: str = ""
    map_schema_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["attach_points"] = [ap.as_tuple() for ap in self.attach_points]
        data["loader"] = self.loader.to_dict()
        data["links"] = [lnk.to_dict() for lnk in self.links]
        return data


@dataclass
class ClassificationResult:
    watch_state: WatchState
    risk_score: int
    reasons: list[str] = field(default_factory=list)
    whitelisted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "watch_state": self.watch_state.value,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "whitelisted": self.whitelisted,
        }


@dataclass
class WatchlistEntry:
    stable_key: str
    current_id: int | None
    state: WatchState
    risk_score: int
    first_seen: str
    last_seen: str
    last_alert_state: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    history: list[dict[str, Any]] = field(default_factory=list)
    object_kind: str = "program"

    def to_dict(self) -> dict[str, Any]:
        return {
            "stable_key": self.stable_key,
            "current_id": self.current_id,
            "state": self.state.value,
            "risk_score": self.risk_score,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_alert_state": self.last_alert_state,
            "metadata": self.metadata,
            "history": self.history,
            "object_kind": self.object_kind,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WatchlistEntry:
        return cls(
            stable_key=data["stable_key"],
            current_id=data.get("current_id"),
            state=WatchState(data.get("state", WatchState.SURVEILLANCE.value)),
            risk_score=int(data.get("risk_score", 0)),
            first_seen=data.get("first_seen", ""),
            last_seen=data.get("last_seen", ""),
            last_alert_state=data.get("last_alert_state"),
            metadata=data.get("metadata", {}),
            history=data.get("history", []),
            object_kind=data.get("object_kind", "program"),
        )


@dataclass
class BpfScanResult:
    programs: list[BpfProgram] = field(default_factory=list)
    maps: list[BpfMap] = field(default_factory=list)
    links: list[BpfLink] = field(default_factory=list)
    boot_id: str = ""
    bpftool_available: bool = False
    programs_loaded: bool = False

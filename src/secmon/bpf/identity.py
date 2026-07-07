"""Stable identity keys for BPF programs and maps."""

from __future__ import annotations

import hashlib
import json
from typing import Iterable

from secmon.bpf.models import AttachPoint, BpfMap, BpfProgram


def _sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def attach_fingerprint(attach_points: Iterable[AttachPoint]) -> str:
    """Hash of sorted attach descriptors, truncated to 16 hex chars."""
    tuples = sorted(ap.as_tuple() for ap in attach_points)
    digest = _sha256_hex(json.dumps(tuples, separators=(",", ":")))
    return digest[:16]


def map_schema_hash(map_ids: list[int], maps_by_id: dict[int, BpfMap]) -> str:
    """SHA256 of sorted map schema tuples referenced by a program."""
    tuples: list[tuple[int, str, int, int]] = []
    for mid in sorted(map_ids):
        m = maps_by_id.get(mid)
        if m:
            tuples.append((mid, m.map_type, m.key_size, m.value_size))
    if not tuples:
        return "none"
    return _sha256_hex(json.dumps(tuples, separators=(",", ":")))[:16]


def program_stable_key(prog: BpfProgram, maps_by_id: dict[int, BpfMap]) -> str:
    """Build stable program key per spec."""
    attach_fp = attach_fingerprint(prog.attach_points)
    schema_hash = map_schema_hash(prog.map_ids, maps_by_id)
    prog.map_schema_hash = schema_hash

    if prog.xlated_sha256:
        return f"prog:{prog.prog_type}:{prog.tag}:{prog.xlated_sha256}:{attach_fp}"

    return f"prog:{prog.prog_type}:{prog.tag}:{prog.name}:{schema_hash}:{attach_fp}"


def map_stable_key(m: BpfMap) -> str:
    """Build stable map key per spec."""
    return (
        f"map:{m.map_type}:{m.name}:{m.key_size}:{m.value_size}:"
        f"{m.max_entries}:{m.flags}:{m.btf_hash}"
    )


def xlated_sha256_from_dump(dump_bytes: bytes) -> str:
    if not dump_bytes:
        return ""
    return _sha256_hex(dump_bytes)

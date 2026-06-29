"""Layer 3: Process forensics + NC-1, NC-6, NC-9."""

from __future__ import annotations

import json
import os
import re

from secmon.audit.base import AuditFinding
from secmon.shell import run_cmd_safe


def run(state: dict, cfg: dict) -> list[AuditFinding]:
    findings: list[AuditFinding] = []

    # Hidden process detection
    proc_pids = set()
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            proc_pids.add(int(entry))
    ps_out = run_cmd_safe(["ps", "-eo", "pid="])
    ps_pids = {int(x) for x in ps_out.split() if x.strip().isdigit()}
    hidden = proc_pids - ps_pids
    if hidden:
        findings.append(
            AuditFinding(
                "CRITICAL", 3, "hidden_proc",
                f"Processes in /proc not in ps: {sorted(hidden)[:10]}",
            )
        )

    # Process name spoofing
    spoof_names = ("kworker", "kthreadd", "migration", "systemd")
    for pid in list(proc_pids)[:200]:
        exe = f"/proc/{pid}/exe"
        comm = f"/proc/{pid}/comm"
        try:
            target = os.readlink(exe)
            name = open(comm, encoding="utf-8", errors="replace").read().strip()
            if any(s in name for s in spoof_names) and target.startswith(("/tmp", "/var/tmp", "/dev/shm")):
                findings.append(
                    AuditFinding("CRITICAL", 3, "proc_spoof", f"Spoofed {name} from {target}")
                )
        except OSError:
            continue

    # Kernel modules
    lsmod = run_cmd_safe(["lsmod"])
    for line in lsmod.splitlines()[1:]:
        parts = line.split()
        if parts and parts[0].startswith(("rootkit", "diamorphine", "reptile")):
            findings.append(
                AuditFinding("CRITICAL", 3, "bad_module", f"Suspicious module: {parts[0]}")
            )

    # NC-1: Docker privilege escalation
    docker_out = run_cmd_safe(["docker", "ps", "--format", "{{.ID}}"])
    if docker_out.strip():
        whitelist = set(cfg.get("whitelist", {}).get("docker_container_whitelist", []))
        for cid in docker_out.split():
            cid = cid.strip()
            if not cid:
                continue
            inspect = run_cmd_safe(["docker", "inspect", cid])
            try:
                data = json.loads(inspect)[0]
            except (json.JSONDecodeError, IndexError):
                continue
            name = data.get("Name", cid).lstrip("/")
            host_config = data.get("HostConfig", {})
            if host_config.get("Privileged"):
                sev = "INFO" if name in whitelist else "CRITICAL"
                findings.append(
                    AuditFinding(sev, 3, "NC-1-privileged", f"Privileged container: {name}")
                )
            for mount in data.get("Mounts", []):
                src = mount.get("Source", "")
                if src == "/var/run/docker.sock":
                    findings.append(
                        AuditFinding("HIGH", 3, "NC-1-sock", f"Docker socket mount: {name}")
                    )
                if src in ("/", "/etc", "/root"):
                    findings.append(
                        AuditFinding("MEDIUM", 3, "NC-1-hostmount", f"Host mount {src}: {name}")
                    )

    # NC-6: Suspicious mounts
    mounts = run_cmd_safe(["cat", "/proc/mounts"])
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mnt, fstype = parts[0], parts[1], parts[2]
        opts = parts[3] if len(parts) > 3 else ""
        if fstype == "tmpfs" and mnt not in ("/tmp", "/run", "/dev/shm", "/run/lock"):
            if not mnt.startswith("/run/user"):
                findings.append(
                    AuditFinding("HIGH", 3, "NC-6-tmpfs", f"Unexpected tmpfs: {mnt}")
                )
        if "bind" in opts and mnt in ("/etc/shadow", "/etc/passwd"):
            findings.append(
                AuditFinding("CRITICAL", 3, "NC-6-bind", f"Dangerous bind mount: {mnt}")
            )
        if mnt == "/proc" and fstype not in ("proc", "procfs"):
            findings.append(
                AuditFinding("CRITICAL", 3, "NC-6-fakeproc", f"Fake /proc mount type: {fstype}")
            )
    for writable in ("/tmp", "/var/tmp", "/dev/shm"):
        for line in mounts.splitlines():
            if line.startswith(f"tmpfs {writable} ") and "noexec" not in line:
                findings.append(
                    AuditFinding("MEDIUM", 3, "NC-6-noexec", f"{writable} missing noexec")
                )

    # NC-9: eBPF integrity
    bpf_disabled = run_cmd_safe(["sysctl", "-n", "kernel.unprivileged_bpf_disabled"]).strip()
    bpf_progs = run_cmd_safe(["bpftool", "prog", "list"])
    if not bpf_progs and "bpftool" in str(run_cmd_safe(["which", "bpftool"])):
        findings.append(AuditFinding("MEDIUM", 3, "NC-9-nobpf", "bpftool available but no programs"))
    elif not run_cmd_safe(["which", "bpftool"]):
        findings.append(AuditFinding("MEDIUM", 3, "NC-9-nobpftool", "bpftool not installed"))
    if bpf_progs and bpf_disabled != "1":
        findings.append(
            AuditFinding("CRITICAL", 3, "NC-9-unpriv", "Unprivileged BPF enabled with programs loaded")
        )
    elif bpf_progs:
        baseline_bpf = state.get("audit_baseline", {}).get("bpf_programs", [])
        current_ids = re.findall(r"^(\d+):", bpf_progs, re.MULTILINE)
        for pid in current_ids:
            if baseline_bpf and pid not in baseline_bpf:
                findings.append(
                    AuditFinding("HIGH", 3, "NC-9-newprog", f"New BPF program: {pid}")
                )
        state.setdefault("audit_baseline", {})["bpf_programs"] = current_ids

    return findings

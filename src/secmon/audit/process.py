"""Layer 3: Process forensics + NC-1, NC-6, NC-9 + advanced checks."""

from __future__ import annotations

import json
import os
import re

from secmon.audit.base import AuditFinding
from secmon.bpf.audit import bpftool_unpriv_check, run_bpf_audit
from secmon.shell import run_cmd_safe

WEB_PARENTS = ("nginx", "apache", "httpd", "php-fpm", "node", "python", "ruby")
SHELL_CHILDREN = ("bash", "sh", "dash", "zsh", "python", "perl", "nc", "ncat", "curl", "wget")
SUSPICIOUS_TMP = ("/tmp", "/var/tmp", "/dev/shm")
INTERPRETER_INJECT = re.compile(
    r"(python\s+-c|perl\s+-e|ruby\s+-e|php\s+-r|/dev/tcp/|bash\s+-i)",
    re.I,
)


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
    whitelisted_tmpfs = set(cfg.get("whitelist", {}).get("tmpfs_mounts", []))
    mounts = run_cmd_safe(["cat", "/proc/mounts"])
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mnt, fstype = parts[0], parts[1], parts[2]
        opts = parts[3] if len(parts) > 3 else ""
        if fstype == "tmpfs" and mnt not in ("/tmp", "/run", "/dev/shm", "/run/lock"):
            if not mnt.startswith("/run/user"):
                if mnt not in whitelisted_tmpfs:
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
    findings.extend(bpftool_unpriv_check(state))
    findings.extend(run_bpf_audit(state, cfg))

    # Process hollowing / code injection via /proc/*/maps
    exclude_pids: set[int] = set(cfg.get("whitelist", {}).get("proc_hollow_exclude_pids", []))
    exclude_comms: set[str] = set(cfg.get("whitelist", {}).get("proc_hollow_exclude_comms", []))

    # Auto-exclude secmon and its child/parent processes — the audit shouldn't flag itself
    secmon_cluster: set[int] = set()
    for pid in proc_pids:
        try:
            cmdline = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\x00", b" ").decode(
                "utf-8", errors="replace"
            )
            if "secmon" in cmdline.lower():
                secmon_cluster.add(pid)
        except OSError:
            continue

    # Walk up parent chain from secmon processes (catches Hermes gateway as parent)
    def _parent_chain(pid: int) -> set[int]:
        chain: set[int] = set()
        while pid > 1:
            chain.add(pid)
            try:
                stat = open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace").read()
                m = re.match(r"\d+ \(.+?\) \S (\d+)", stat)
                if not m:
                    break
                pid = int(m.group(1))
                if pid in chain:
                    break  # loop
            except OSError:
                break
        return chain

    for spid in list(secmon_cluster):
        secmon_cluster |= _parent_chain(spid)
    # Walk down to find children of any secmon-cluster PID
    for pid in proc_pids:
        try:
            stat = open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace").read()
            m = re.match(r"\d+ \(.+?\) \S (\d+)", stat)
            if m and int(m.group(1)) in secmon_cluster:
                secmon_cluster.add(pid)
        except OSError:
            continue

    exclude_pids.update(secmon_cluster)
    # Also auto-exclude by comm name for dynamically spawned processes
    exclude_comms |= {"secmon", "secmon-audit", "secmon.sh", "audit.sh"}
    for pid in list(proc_pids)[:300]:
        if pid in exclude_pids:
            continue
        # Check if this process comm is in the exclusion list
        if exclude_comms:
            try:
                comm_name = open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace").read().strip()
                if comm_name in exclude_comms:
                    continue
            except OSError:
                pass
        maps_path = f"/proc/{pid}/maps"
        try:
            with open(maps_path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    perms = parts[1]
                    pathname = parts[-1] if len(parts) > 5 else ""
                    if "x" not in perms:
                        continue
                    if pathname.endswith("(deleted)") and pathname not in ("", "[heap]", "[stack]"):
                        findings.append(
                            AuditFinding(
                                "CRITICAL", 3, "proc_hollow_deleted",
                                f"Deleted executable mapping in pid {pid}: {pathname}",
                                {"pid": pid, "path": pathname},
                            )
                        )
                    elif pathname.startswith("[anon:") or (
                        pathname in ("", "[heap]") and "rwx" in perms
                    ):
                        findings.append(
                            AuditFinding(
                                "CRITICAL", 3, "proc_hollow_anon",
                                f"Anonymous executable mapping in pid {pid}: {perms} {pathname}",
                                {"pid": pid},
                            )
                        )
                    elif "rwx" in perms and not pathname.startswith("/"):
                        findings.append(
                            AuditFinding(
                                "CRITICAL", 3, "proc_hollow_rwx",
                                f"RWX anonymous region in pid {pid}",
                                {"pid": pid},
                            )
                        )
        except OSError:
            continue

    # Suspicious parent-child process lineage
    proc_info: dict[int, dict] = {}
    for pid in proc_pids:
        stat_path = f"/proc/{pid}/stat"
        cmdline_path = f"/proc/{pid}/cmdline"
        try:
            stat_line = open(stat_path, encoding="utf-8", errors="replace").read()
            # comm is field 2 in parentheses; ppid is field 4 after comm
            m = re.match(r"\d+ \((.+?)\) \S (\d+)", stat_line)
            if not m:
                continue
            comm, ppid = m.group(1), int(m.group(2))
            cmdline = open(cmdline_path, "rb").read().replace(b"\x00", b" ").decode(
                "utf-8", errors="replace"
            ).strip()
            exe = ""
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                pass
            proc_info[pid] = {"comm": comm, "ppid": ppid, "cmdline": cmdline, "exe": exe}
        except OSError:
            continue

    for pid, info in proc_info.items():
        ppid = info["ppid"]
        parent = proc_info.get(ppid)
        if not parent:
            continue
        pcomm = parent["comm"].lower()
        ccomm = info["comm"].lower()
        if any(w in pcomm for w in WEB_PARENTS) and any(s in ccomm for s in SHELL_CHILDREN):
            findings.append(
                AuditFinding(
                    "HIGH", 3, "proc_lineage_web_shell",
                    f"Web process {ppid}/{pcomm} spawned shell {pid}/{ccomm}",
                    {"parent_pid": ppid, "child_pid": pid},
                )
            )
        if INTERPRETER_INJECT.search(info["cmdline"]):
            findings.append(
                AuditFinding(
                    "CRITICAL", 3, "proc_lineage_inject",
                    f"Interpreter injection in pid {pid}: {info['cmdline'][:120]}",
                    {"pid": pid},
                )
            )

    # Unexpected root execution from temp/writable paths
    for pid, info in proc_info.items():
        status_path = f"/proc/{pid}/status"
        try:
            status = open(status_path, encoding="utf-8", errors="replace").read()
            uid_line = next((ln for ln in status.splitlines() if ln.startswith("Uid:")), "")
            uids = uid_line.split()
            if len(uids) < 2 or uids[1] != "0":
                continue
        except OSError:
            continue
        exe = info.get("exe", "")
        if any(exe.startswith(p) for p in SUSPICIOUS_TMP):
            findings.append(
                AuditFinding(
                    "CRITICAL", 3, "proc_root_tmp",
                    f"Root process from temp path: pid {pid} {exe}",
                    {"pid": pid, "exe": exe},
                )
            )
        elif "(deleted)" in exe:
            findings.append(
                AuditFinding(
                    "CRITICAL", 3, "proc_root_deleted",
                    f"Root process with deleted binary: pid {pid} {exe}",
                    {"pid": pid},
                )
            )

    # Kernel / module tampering signals
    tainted = run_cmd_safe(["cat", "/proc/sys/kernel/tainted"])
    if tainted.strip() not in ("0", ""):
        findings.append(
            AuditFinding(
                "HIGH", 3, "kernel_tainted",
                f"Kernel tainted flag set: {tainted.strip()}",
            )
        )
    lockdown = run_cmd_safe(["cat", "/proc/sys/kernel/lockdown"])
    if lockdown.strip() and lockdown.strip() not in ("0", "[none]"):
        findings.append(
            AuditFinding("INFO", 3, "kernel_lockdown", f"Kernel lockdown: {lockdown.strip()}")
        )
    modules_disabled = run_cmd_safe(["sysctl", "-n", "kernel.modules_disabled"]).strip()
    ab = state.setdefault("audit_baseline", {})
    sysctl_baseline: dict = ab.setdefault("sysctl", {})
    for key, cmd in (
        ("modules_disabled", ["sysctl", "-n", "kernel.modules_disabled"]),
        ("kptr_restrict", ["sysctl", "-n", "kernel.kptr_restrict"]),
        ("perf_event_paranoid", ["sysctl", "-n", "kernel.perf_event_paranoid"]),
    ):
        val = run_cmd_safe(cmd).strip()
        prev = sysctl_baseline.get(key)
        if prev is not None and prev != val and key == "modules_disabled" and val == "0":
            findings.append(
                AuditFinding(
                    "CRITICAL", 3, "kernel_sysctl_change",
                    f"Security sysctl {key} relaxed: {prev} -> {val}",
                )
            )
        sysctl_baseline[key] = val
    if modules_disabled == "0":
        skip_modules = cfg.get("hardening", {}).get("skip_kernel_modules_check", False)
        lsmod_lines = lsmod.splitlines()[1:] if lsmod else []
        if skip_modules:
            # Still track changes but don't alert on enabled state alone
            pass
        elif len(lsmod_lines) > 5:
            findings.append(
                AuditFinding(
                    "HIGH", 3, "kernel_modules_enabled",
                    "Kernel module loading enabled with multiple modules loaded",
                )
            )

    return findings

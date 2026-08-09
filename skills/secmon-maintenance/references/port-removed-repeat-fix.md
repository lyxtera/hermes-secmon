# port_removed repeat-forever fix — delegation spec + regression recipe

Session 2026-08-09. Symptom: `🟠 HIGH — Audit (Port Removed): Listening port removed: 30141`
on every 15-min tick, forever. Port 30141 was the intentionally-removed `@agegr/pi-web`
UI (uninstalled the prior day). Detection was technically true (port gone) but a false
alarm (removal was deliberate), and the check had no dedup.

## Root cause

`src/secmon/audit/network.py` (Layer 2, `run()`):
- `ab = state.setdefault("audit_baseline", {})`, `known_ports = ab.setdefault("known_ports", {})`
- Baseline only ever grows: `known_ports.update({str(k): v for k, v in current_ports.items()})`
  runs every audit, but nothing ever removes entries for ports no longer listening, and
  nothing records that a removal was already alerted.
- Removal loop: `for port in set(map(int, known_ports)) - set(current_ports):` → appends
  `AuditFinding("HIGH", 2, "port_removed", f"Listening port removed: {port}")` whenever a
  known port is absent. A port that stays gone is in this diff EVERY audit → repeat alert
  every tick indefinitely.
- Contrast: the BPF watcher already emits findings only on state transitions and absorbs
  VANISHED programs silently. The port check never got that treatment.

## Stopgap (config, immediate)

```yaml
# ~/.hermes/secmon/config.yaml (symlinked from /etc/secmon/config.yaml)
whitelist:
  port_removed:
    - 30141
```

Verified: `python -m secmon --tick --config /root/.hermes/secmon/config.yaml` exits 0
with no output (silent) after the change. No baseline reset needed.

## Asymmetry bug in existing whitelist

The port WAS already in `whitelist.new_listen_ports: [30141]` (whitelisted when it first
appeared as a new listener). That key only gates the `new_listen_port` finding — it does
NOT gate `port_removed`. So a port can be whitelisted for "expected to listen" yet still
alert when it disappears. Cover removals in `port_removed`, not `new_listen_ports`.

## Root-cause code fix (transition semantics)

Spec handed to the Pi coding agent (delegate_task → `pi -p`), local-only, no commit:

1. `ab.setdefault("reported_removed_ports", [])` — persist in audit baseline (state.json).
2. In the removal loop: if port already in `reported_removed_ports` → skip (no repeat
   finding). On first emit, append the port to the list.
3. Keep the two existing whitelist checks untouched: static `whitelist.port_removed`
   (port ints/strs) and `whitelist.port_removed_processes` (transient process-name match
   via `_re.search(r'"([^"]+)"', known_ports_line)`). Whitelisted ports never alert and
   are NOT recorded.
4. Prune: any port in `reported_removed_ports` that is listening again (in
   `current_ports`) must be removed from the list → if it later disappears AGAIN it
   re-alerts (true transition semantics).
5. Optionally prune gone-and-reported entries from `known_ports` to stop baseline growth;
   keep the final `known_ports.update(current)` line.
6. Finding format unchanged: `AuditFinding("HIGH", 2, "port_removed", ...)`.

## Regression test recipe (tests/test_push_95.py style)

Reuse existing fixtures (`cfg`, `state`, `mock_commands` — see
`test_network_port_baseline_changes` in tests/test_push_95.py, which mocks
`ss -tlnp`, `iptables -L INPUT -n`, `iptables -L -n`, `ip link show`, `ip neigh show`
and patches `os.path.isfile` → False):

- Run 1: `state["audit_baseline"]["known_ports"] = {"22": "old", "3000": "old3000"}`
  (state carries no `reported_removed_ports` yet); mock `ss` shows 22 but NOT 3000 →
  assert exactly one `port_removed` for 3000.
- Run 2: same state passed along (now has `reported_removed_ports` containing 3000),
  mock `ss` still lacks 3000 → assert NO `port_removed` finding.
- Whitelist case: put 3000 in `cfg["whitelist"]["port_removed"]` → even run 1 produces no
  finding for it.

## Verification commands

```bash
cd /root/.hermes/plugins/secmon && source venv/bin/activate \
  && python -m pytest tests/ -v --tb=short --no-cov          # all green
timeout 120 python -m secmon --check --config /root/.hermes/secmon/config.yaml; echo EXIT=$?
```

(pytest must be installed in the plugin venv first: `pip install pytest pytest-cov`.)

## Pi invocation notes (system pi 0.73.1)

- `pi -p '<task>' --provider openrouter --no-extensions` — the `--no-extensions` flag is
  REQUIRED because `~/.pi/agent/settings.json` registers webui packages whose extensions
  crash pi 0.73.1 with `pi.registerEntryRenderer is not a function`.
- Export `OPENROUTER_API_KEY` from `/root/.hermes/.env` (set -a; source; set +a).
- Use `timeout 600` around each invocation; workdir = plugin repo root.
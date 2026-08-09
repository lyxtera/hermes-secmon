# Secret-pattern prose/code/type false positives — root cause, delegation spec, verification

Session 2026-08-09. User's actual concern (higher priority than the port alert): secmon
"finds" secrets in files that contain no secrets — `secret_pattern` HIGH findings on
files that merely mention `apiKey:`/`API key` in code, types, or UI strings.

## Reproduction (do this FIRST, before any code change)

Never trust the finding message alone. Confirm the flagged files exist, then run the
scanner's exact logic over them:

```bash
# 1. Files flagged by the audit (truncated paths in the finding message):
#    /root/fork/.../pi-extension-brave-search/index.ts
#    /root/fork/.../pi-extension-cursor-composer/index.ts
#    /root/fork/.../pi-extension-cursor-composer/DEVELOPMENT.md

# 2. Confirm they exist and grep for the actual matched tokens:
for f in <flagged files>; do echo "== $f"; grep -niE "api[_-]?key|BEGIN .*PRIVATE|AWS_SECRET_ACCESS_KEY" "$f" | head -8; done

# 3. Standalone repro script (exact SECRET_PATTERNS + value-extraction logic):
#    writes pattern + line no + val for every hit — see the SKILL.md section
#    "Secret Pattern — Prose / Code / Type-Annotation Context False Positives"
#    for the extraction snippet. Expected hit shapes that prove the bug:
#      val='if (workspaceKey) return { apiKey: ...'   ← object property, not a secret
#      val='ctx.ui.notify("Brave Search setup cancelled: no API key...'  ← UI string
#      val='onTextDelta?: (delta: string, ...'        ← TS function type
```

## Root cause (2 bugs)

1. `api[_-]?key\s*[:=]` (case-insensitive) matches the token in ANY context.
2. The value check takes a ±200-char window around the match and splits on the FIRST
   `=` in the whole window — so arbitrary code/prose passes `len >= 8` and the tiny
   placeholder list. The value is never required to be on the same line as the key.

## Fix spec (delegated to Pi CLI, `threat_intel.py`)

- Extract the ACTUAL matched line, not a window.
- Flag ONLY same-line quoted literals or bare tokens after `=`/`:` (no spaces, len ≥ 8).
- Skip: env-var indirection (`process.env[...]`, `getEnv(`, `env(`, `readEnvValue(`, `.env`),
  type annotations (`apiKey?: string;`, `apiKey: string`, EOL/`;`), prose (spaces/sentence),
  code expressions (`( ) [ ] . => { }`, template interpolation).
- Extend placeholder list: "string", "none", "null", "undefined", "true", "false", "secret", "key".
- Leave PEM private-key + `AWS_SECRET_ACCESS_KEY` regexes unchanged (already specific).

## Delegation prompt essentials (what made the subagent succeed)

- Must export `OPENROUTER_API_KEY` from `/root/.hermes/.env` and run
  `pi -p '...' --provider openrouter --no-extensions` (webui extensions crash pi 0.73.1).
- `timeout 600` around each pi call; workdir = plugin repo.
- Explicitly forbid: git commit/push, touching `/var/lib/secmon/state.json`, config files.
- Tests: `cd ~/.hermes/plugins/secmon && source venv/bin/activate && python -m pytest tests/ -q --no-cov`
  (with SECMON_* env vars unset — see test-suite-pitfalls.md).
- Require deliverables: diffs + pytest counts + repro outcome + --check grep + caveats.

## Verification (parent agent must re-run, never trust the subagent's numbers)

```bash
cd /root/.hermes/plugins/secmon && source venv/bin/activate
unset SECMON_OWN_IP SECMON_ANOMALY_COOLDOWN_MINUTES SECMON_OVERRIDE_SSH_FAILED_24H_MIN_DELTA
python -m pytest tests/ -q --tb=short --no-cov          # expect all green
python3 /tmp/repro_secret_scan.py <the 3 flagged files>  # expect zero hits after fix
timeout 120 python -m secmon --check --config /root/.hermes/secmon/config.yaml 2>&1 | grep -i secret_pattern
```

## Regression test cases

`apiKey?: string;` → no flag · prose "Save the API key which you created..." → no flag ·
`apiKey = "sk-0123456789abcdef..."` → flag · `API_KEY=AKIAIOSFODNN7EXAMPLE` → flag ·
`.env.example` placeholder → no flag · PEM block → flag.

## Implemented 2026-08-09 — final design + surprises (deviations from the spec above)

Executed in `threat_intel.py` with regression file `tests/test_secret_scan_false_positives.py` (35 tests).

**What the spec did NOT anticipate:**

1. **JSON quoted keys never matched the old regex.** `api[_-]?key\s*[:=]` does NOT match
   `{"apiKey": "sk-..."}` — after `apiKey` comes `"` (closing quote), not `:`/`=`. The pattern
   was widened to `["']?api[_-]?key["']?\s*[:=]` (re.I) so JSON configs with real keys are
   detectable. `apiKey?: string;` STILL never matches (the `?` blocks the `[:=]`), so TS
   optional-type annotations are skipped by the regex itself — don't rely on the value
   checker for those.
2. **Quoted literals must tolerate trailing structural chars.** `{"apiKey": "sk-abc123"}` has
   `}` right after the closing quote. Naive code-char rejection kills real JSON secrets.
   Final rule (helper `_real_secret_value(sample, m)`): if the rest starts with `"`/`'`,
   extract ONLY the quoted content (up to the closing quote) — trailing `}`, `,`, `;`,
   `// comment` are structural and ignored. The code-expression / env-marker / whitespace
   rejection applies ONLY to bare (unquoted) tokens. Backtick literals are NOT quote-treated
   — they fall to the bare path (interpolated ones die on `{`/`}`).
3. **Specific patterns get different gates.** Loop dispatches by index over `SECRET_PATTERNS`:
   PEM (idx 0) → flag on marker alone (a `-----BEGIN ... PRIVATE KEY-----` line's "rest" is
   empty, so same-line validation would ALWAYS skip it — direct flag preserves old behavior);
   AWS (idx 1) → placeholder-gate only (`AWS_SECRET_ACCESS_KEY=your-key-here` stays
   suppressed, real values flag); apiKey (idx 2) → strict `_real_secret_value`.
4. **Testability hoist:** scan roots moved to module constant `SECRET_SCAN_ROOTS`
   (defaults `/tmp /var/tmp /dev/shm /root`; WEB_ROOTS still appended). Tests monkeypatch it
   to a tmp dir — without this, `_scan_secrets` walks the real filesystem with no config knob.

**Test-writing pitfall (hit in-session):** scanning a shared root accumulates findings from
earlier-written files — a second `_assert_pattern` in the same test then sees 2 findings and
fails `len(hits) == 1`. Every `_run_case` writes its file into a fresh subdirectory and
re-points `SECRET_SCAN_ROOTS` at that subdir. Fork-repo integration test (absolute paths)
is `@pytest.mark.skipif(not os.path.isdir(...))`-guarded so it self-skips off this machine.

**Tool-output pitfall:** `read_file`/terminal render long lines truncated with `...`/`***` —
indistinguishable from literally-scrubbed file content (the fork repo sources ARE scrubbed:
`apiKey: ***`, `apiKey: proces...EY]`). When judging whether a file really contains
something, verify byte-level with python `len(line)` / `repr(line)`, never the display.

**Verification (all re-run and green this session):** new file 35 passed · full suite
`env -u SECMON_OWN_IP python -m pytest tests/ -q` → 227 passed, 4 skipped · repro over the 3
fork files → 0 `secret_pattern` · `python -m secmon --check ... | grep -i secret_pattern`
→ no lines (grep EXIT=1). Known-fork trivia: the 3 files" repo is at
`/root/fork/pi-coding-agent-forge/`.
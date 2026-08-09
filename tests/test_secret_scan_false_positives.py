"""Regression tests for the secret_pattern content scanner.

Covers the false-positive bug where apiKey/API_KEY mentions in code, type
annotations, env-var references and prose were flagged as exposed secrets,
while real same-line literal values (and PEM/AWS markers) must still fire.
"""

from __future__ import annotations

import itertools
import os
from pathlib import Path

import pytest

from secmon.audit import threat_intel

_CASE = itertools.count()


@pytest.fixture
def secret_scan_roots(tmp_path, monkeypatch):
    """Point the secret content scanner at a throwaway directory."""
    monkeypatch.setattr(threat_intel, "SECRET_SCAN_ROOTS", [str(tmp_path)])
    monkeypatch.setattr(threat_intel, "WEB_ROOTS", [])
    return tmp_path


def _run_case(cfg, root: Path, name: str, content: str):
    """Write one file into its own private scan root and scan only that root."""
    case_dir = root / f"case_{next(_CASE)}"
    case_dir.mkdir(exist_ok=True)
    (case_dir / name).write_text(content)
    threat_intel.SECRET_SCAN_ROOTS = [str(case_dir)]
    return [
        f for f in threat_intel._scan_secrets(cfg)
        if f.check_id == "secret_pattern"
    ]


def _assert_no_pattern(cfg, root, name, content):
    hits = _run_case(cfg, root, name, content)
    assert not hits, f"unexpected secret_pattern findings for {name}: {hits}"


def _assert_pattern(cfg, root, name, content):
    hits = _run_case(cfg, root, name, content)
    assert len(hits) == 1, f"expected exactly one secret_pattern finding for {name}, got {hits}"


# --- negatives: code, type annotations, env refs, prose -------------------

def test_no_finding_type_annotation_and_env_ref(cfg, secret_scan_roots):
    _assert_no_pattern(
        cfg, secret_scan_roots, "types.ts",
        "type Opts = {\n"
        "\tapiKey?: string;\n"
        "\tapiKey: string;\n"
        "\tcreds: { apiKey: process.env.SOME_KEY };\n"
        "};\n",
    )


def test_no_finding_ts_property_without_value(cfg, secret_scan_roots):
    _assert_no_pattern(cfg, secret_scan_roots, "options.ts", "\tapiKey:;\n")


def test_no_finding_prose(cfg, secret_scan_roots):
    _assert_no_pattern(
        cfg, secret_scan_roots, "README.md",
        "Save the API key: which you created and paste it below.\n"
        "Paste your Brave Search API key into the input.\n",
    )


def test_no_finding_env_indirection_variants(cfg, secret_scan_roots):
    _assert_no_pattern(
        cfg, secret_scan_roots, "env.ts",
        "const a = { apiKey: process.env[ENV_KEY], source: \"environment\" };\n"
        "const b = { apiKey: getEnv(\"SOME_KEY\") };\n"
        "const c = { apiKey: readEnvValue(envPath, ENV_KEY) };\n"
        "const d = { apiKey: env(\"SOME_KEY\") };\n"
        "const e = { apiKey: configValue, source: \"workspace .env\", path: p };\n",
    )


def test_no_finding_code_expressions(cfg, secret_scan_roots):
    _assert_no_pattern(
        cfg, secret_scan_roots, "ui.ts",
        "const apiKey = await ctx.ui.input(\"API key\", \"Paste your API key\");\n"
        "const trimmedApiKey = apiKey?.trim();\n"
        "return { apiKey: config.creds, mode: \"x\" };\n"
        "onTextDelta?: (delta: string, accumulated: string) => void;\n",
    )


def test_no_finding_redacted_placeholder(cfg, secret_scan_roots):
    _assert_no_pattern(cfg, secret_scan_roots, "scrubbed.ts", "\tapiKey: ***\n")
    _assert_no_pattern(cfg, secret_scan_roots, "scrubbed2.ts", "\tapiKey: *** source: \"x\"\n")


def test_no_finding_env_example_and_placeholder(cfg, secret_scan_roots):
    # .env.example is skipped wholesale (existing behavior)
    _assert_no_pattern(cfg, secret_scan_roots, "app.env.example", "API_KEY=your-key-here\n")
    # a non-example file with an explicit placeholder is skipped too
    _assert_no_pattern(cfg, secret_scan_roots, "config.sh", "API_KEY=your-key-here\n")
    _assert_no_pattern(cfg, secret_scan_roots, "config2.sh", "API_KEY=\"your-key-here\"\n")


def test_no_finding_aws_placeholder(cfg, secret_scan_roots):
    _assert_no_pattern(cfg, secret_scan_roots, "aws.sh", "AWS_SECRET_ACCESS_KEY=your-key-here\n")


# --- positives: real same-line literal secrets ----------------------------

def test_finding_api_key_quoted(cfg, secret_scan_roots):
    _assert_pattern(cfg, secret_scan_roots, "creds.json",
                    '{"apiKey": "sk-0123456789abcdef"}\n')
    _assert_pattern(cfg, secret_scan_roots, "creds.txt",
                    'apiKey = "0123456789abcdef0123456789abcdef"\n')
    _assert_pattern(cfg, secret_scan_roots, "creds2.txt",
                    "apiKey: 'ghp_xxxxxxxxxxxx',\n")


def test_finding_api_key_bare_token(cfg, secret_scan_roots):
    _assert_pattern(cfg, secret_scan_roots, "config.sh", "API_KEY=AKIAIOSFODNN7EXAMPLE\n")


def test_finding_pem_private_key(cfg, secret_scan_roots):
    _assert_pattern(
        cfg, secret_scan_roots, "cert.txt",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
    )


def test_finding_aws_secret_access_key(cfg, secret_scan_roots):
    _assert_pattern(
        cfg, secret_scan_roots, "aws.sh",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    )


# --- unit-level semantics of the same-line validator ----------------------

@pytest.mark.parametrize(
    "rest, expected",
    [
        ('"sk-0123456789abcdef"', "sk-0123456789abcdef"),   # quoted literal
        ('"sk-0123456789abcdef"}', "sk-0123456789abcdef"),  # JSON object close
        ('"sk-0123456789abcdef",', "sk-0123456789abcdef"),  # trailing comma
        ('"sk-12345678" // comment', "sk-12345678"),        # trailing comment
        ("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),   # bare token
        ("'ghp_xxxxxxxxxxxx',", "ghp_xxxxxxxxxxxx"),        # trailing comma
        ('"0123456789abcdef0123456789abcdef"', "0123456789abcdef0123456789abcdef"),
        ("***", None),                                      # redaction marker
        ("your-key-here", None),                            # placeholder
        ("string;", None),                                  # type annotation
        ("string", None),                                   # type annotation
        ("process.env.SOME_KEY }", None),                   # env ref
        ("getEnv(ENV_KEY)", None),                          # env indirection
        ("readEnvValue(p, K)", None),                       # env indirection
        ("config.apiKey", None),                            # member access
        ("fn()", None),                                     # call expression
        ("a => b", None),                                   # arrow expression
        ("Save the API key: which you created", None),      # prose (spaces)
        ("undefined", None),                                # keyword placeholder
        ("null", None),                                     # keyword placeholder
        ("secret", None),                                   # keyword placeholder
        ("false", None),                                    # keyword placeholder
    ],
)
def test_real_secret_value_semantics(rest, expected):
    sample = f"const x = {{\napiKey: {rest}\n}};\n"
    m = threat_intel.SECRET_PATTERNS[2].search(sample)
    assert m is not None, f"pattern did not match rest={rest!r}"
    assert threat_intel._real_secret_value(sample, m) == expected


# --- integration: the three original false-positive files -----------------

FORK_DIR = "/root/fork/pi-coding-agent-forge"
FORK_EXTS = [
    f"{FORK_DIR}/pi-extension-brave-search",
    f"{FORK_DIR}/pi-extension-cursor-composer",
]


@pytest.mark.skipif(
    not all(os.path.isdir(d) for d in FORK_EXTS),
    reason="fork reproduction repo not present on this machine",
)
def test_no_findings_on_fork_repo_files(cfg, monkeypatch):
    """The real open-source files that used to be flagged must be clean."""
    monkeypatch.setattr(threat_intel, "SECRET_SCAN_ROOTS", list(FORK_EXTS))
    monkeypatch.setattr(threat_intel, "WEB_ROOTS", [])
    findings = threat_intel._scan_secrets(cfg)
    flagged = [f for f in findings if f.check_id == "secret_pattern"]
    assert not flagged, f"secret_pattern still fired: {flagged}"
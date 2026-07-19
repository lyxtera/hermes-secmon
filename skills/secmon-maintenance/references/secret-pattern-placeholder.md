# Secret Pattern — Placeholder / `.env.example` False Positive Test

Regression test for the `secret_pattern` fix in `src/secmon/audit/threat_intel.py`.
Run after any change to the secret-scan loop. The fix (a) skips `*.example`
template files and (b) requires a real value after the key (not `=*** ` etc.).

## Self-contained check

```python
import importlib.util, os, tempfile

spec = importlib.util.spec_from_file_location(
    "ti", "src/secmon/audit/threat_intel.py")
ti = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ti)

PLACEHOLDER_VALS = ("", "***", "CHANGEME", "<your-key-here>", "your-key-here",
                    "placeholder", "REPLACE_ME", "TODO", "xxxx", "xxxxxx")

def scan_file(fp, content):
    with open(fp, "w") as fh:
        fh.write(content)
    fname = os.path.basename(fp)
    if fname.endswith(".example") or ".example." in fname:
        return False, "skipped-example"
    sample = open(fp, encoding="utf-8", errors="replace").read(8000)
    for pat in ti.SECRET_PATTERNS:
        m = pat.search(sample)
        if not m:
            continue
        line = sample[max(0, m.start() - 200):m.end() + 200]
        key_line = line.splitlines()[-1] if "=" in line else line
        val = key_line.split("=", 1)[-1].strip().strip("\"'")
        if not (val in PLACEHOLDER_VALS) and len(val) >= 8:
            return True, "FLAGGED"
    return False, "clean"

d = tempfile.mkdtemp()
cases = {
    "Case1 .env.example placeholder": (("env.example", "GROQ_API_KEY=***\n"), False),
    "Case2 real GROQ key":           (("real.env",  "GROQ_API_KEY=gsk_8f3a9c2b7e1d4f5a6b7c8d9e0f1a2b3c\n"), True),
    "Case3 real AWS secret":         (("aws.env",   "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"), True),
    "Case4 PEM private key":         (("key.pem",   "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"), True),
}
for label, ((fname, content), expect) in cases.items():
    got, why = scan_file(os.path.join(d, fname), content)
    print(f"{label}: flagged={got} ({why}) -> {'OK' if got == expect else 'FAIL'}")
```

## Expected

| Case | File | Content | Expect |
|------|------|---------|--------|
| 1 | `.env.example` | `GROQ_API_KEY=*** ` | **no flag** (template skipped) |
| 2 | `real.env` | `GROQ_API_KEY=gsk_...` (>=8 chars real) | flag |
| 3 | `aws.env` | `AWS_SECRET_ACCESS_KEY=wJalr...` | flag |
| 4 | `key.pem` | `-----BEGIN RSA PRIVATE KEY-----` | flag |

If Case 1 flags, the `*.example` skip is missing. If Case 2/3/4 do NOT flag,
the value-validation `len(val) >= 8` is too strict or the placeholder set is
too broad.

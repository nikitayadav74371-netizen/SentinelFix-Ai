# Sentinel AI AI
**An Autonomous Security Verification and Remediation Agent for Web Applications**

```
Application -> Security Analyst -> Vulnerability Found -> Exploit Validator -> Confirmed Finding
   -> Patch Generator -> Security Judge --PASS--> Regression Tests -> VERIFIED SECURITY FIX
                              \--REJECT--> Regenerate Patch (up to 3 attempts, then manual review)
```

## Quick start (Windows)
1. Install **Python 3.10+** (tick "Add to PATH") and **git** (only needed for GitHub scans).
2. Double-click **`run.bat`**. It creates a virtual environment, installs dependencies, and opens http://localhost:8000.
3. *(Optional)* Keep **Ollama** running for LLM-assisted fixes: `ollama serve` (your `qwen2.5-coder:7b` is auto-selected).

Linux/macOS: `./run.sh`.  No UI: `python cli_scan.py <source_dir> <output_dir>`.

## Using it
- **Local folder / file** - paste a folder (or a single file) path, e.g. `C:\Projects\my-app`.
- **GitHub repository** - paste `https://github.com/owner/repo`. The repo is verified reachable, cloned into `workspace/`, checked to contain scannable source, then scanned file by file. Optionally add a local path to see whether your local copy matches the repo.
- Watch the pipeline run live, expand findings to see the diff and the Judge's verdict, then **Download patched project (.zip)**.
- Your original files are **never modified**. The ZIP contains `patched_project/`, `SENTINELFIX_REPORT.md` and `sentinelfix_report.json`.

## Languages & what is detected
| Language | Detected |
|---|---|
| Python | SQL injection (AST-based, follows variables into `.execute()`), hardcoded passwords/secret keys, eval/exec, os.system / `shell=True`, pickle, unsafe YAML, weak hashes, Flask `debug=True`, path traversal |
| JavaScript/TS | hardcoded credentials, DOM XSS (`innerHTML`, `document.write`), eval / `new Function`, token in localStorage |
| PHP | SQL injection via `$_GET/$_POST`, XSS echo, eval, file inclusion, command exec, unserialize, hardcoded creds, md5 |
| C / C++ | `gets`, `strcpy`, `strcat`, `sprintf`, unbounded `scanf`, `system`/`popen`, format strings, hardcoded creds |
| HTML / CSS | inline-handler injection, CSS `expression()`, insecure `@import`; all files get secret/key scanning |

## How fixes work (important - read this)
**Built-in verified fixes** (no LLM needed) - deterministic, minimal diffs:
- Python SQL injection -> parameterized query (`?` placeholders + bound parameters)
- Hardcoded Python secrets / Flask `secret_key` -> environment variables; a `.env` is generated (and added to `.gitignore`) so the app keeps working. A tiny dependency-free loader is inserted.
- JS hardcoded password -> SHA-256 hash comparison via `crypto.subtle`; `innerHTML` -> `textContent`
- Flask `debug=True` -> `debug=False`

**LLM-assisted fixes** (Ollama) for everything else (eval, command injection, C/C++ buffers, ...). LLM output is treated as *untrusted*: it is accepted only if a **real** compiler/interpreter verifies its syntax (node, python, gcc/g++, php if installed), it plausibly relates to the code it replaces, and it removes the vulnerable pattern. Otherwise the finding is marked **MANUAL REVIEW REQUIRED** and nothing is changed.

## Honest limitations
- **Static analysis, not a pentest.** "Verified" means: vulnerable pattern removed, file still parses, no functions deleted. The application is *never executed*. Re-run your own tests after applying patches.
- Rule-based detection can miss issues (and rarely over-flag). It is a strong first pass, not a guarantee.
- SQL auto-fix handles string concatenation / f-string queries in Python; exotic query builders go to LLM/manual review.
- The `.env` loader reads `.env` from the directory you launch the app in.
- PHP fixes need `php` on PATH to be auto-accepted (otherwise manual review). C/C++ checks compile files in isolation.
- Client-side JS cannot truly hide a password; the hash removes the plaintext but real authentication belongs on a server.

## Project layout
`backend/` FastAPI app (`main.py`), agents (`analyst`, `validator`, `judge`, `regression`, `orchestrator`), `rules/` per-language detection, `patchers/` deterministic + LLM fixes, `scanner/` file walking + git. `frontend/` single-page UI. `workspace/` job output (safe to delete).

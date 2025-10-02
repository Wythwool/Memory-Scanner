# memscan — Windows user‑mode memory scanner

`oner.py` is a fast Windows user‑mode memory scanner. It searches for byte signatures (with wildcards) and strings (ASCII/UTF‑16LE), supports **live scanning**, and can export clean **JSON reports**.

## Features

* Scan readable committed pages of a target process (no kernel drivers).
* Byte signatures with wildcards (`??`, `**`, `wild`).
* String extraction (ASCII + UTF‑16LE) with regex filters.
* Live mode: periodic rescans with optional *diff‑only* output.
* JSON report: process metadata + precise hit locations.
* Minimal dependencies, pure Python + WinAPI (ctypes).

## Requirements

* **Windows** (x64/x86). User‑mode only.
* Python 3.9+.
* `psutil` (`pip install psutil`).
* Sufficient rights to read the target process (`PROCESS_VM_READ`). Run shell as Administrator if needed.

## Install

```bash
pip install psutil
```

## Quick start

By PID:

```bash
python oner.py --pid 1234 --sig "StackPivot=90 90 ?? E8" --find "(http|https)://" --json-out out.json
```

By process name (substring allowed), live 2s, show only new hits:

```bash
python oner.py --name notepad --sig "WOW=48 8B ?? 05 ?? E8" --live 2 --diff-only
```

Using a signature file:

```bash
python oner.py --name chrome --sig-file sigs.txt --find "api_key=.{16,}" --json-out results.json
```

## Signatures

* **Syntax:** space‑separated hex bytes: `48 8B 05`. Wildcards: `??` (also `**` or `wild`) match any single byte.
* **Inline:** `--sig NAME=48 8B ?? 05` or just `--sig "48 8B ?? 05"` (auto names: `sig_1`, `sig_2`, ...).
* **File format:** one per line. Comments start with `#`.

  ```text
  # name=pattern
  MZ=4D 5A
  StackPivot=90 90 ?? E8
  64bitThunk=48 83 EC ?? 48 8B ??
  ```

## String filters

* Extracts ASCII and UTF‑16LE strings (disable UTF‑16 with `--no-utf16`).
* Minimum length via `--min-len` (default: 4).
* Filter strings with one or more regexes: `--find "password=.+" --find "https?://"`.

## Live mode

Rescans the process on an interval and tracks *new* hits.

```bash
python oner.py --name app --sig-file sigs.txt --find "token_[A-Za-z0-9]+" --live 3 --diff-only
```

* `--live <seconds>` — rescan interval.
* `--diff-only` — print only previously unseen hits (state kept in memory while running).

## JSON output

Write full report with `--json-out file.json`.

### Structure

```jsonc
{
  "meta": {
    "pid": 1234,
    "name": "notepad.exe",
    "create_time": "2025-10-02T14:03:12",
    "ts": "2025-10-02T11:24:33Z"
  },
  "hits": {
    "patterns": [
      { "name": "MZ", "pattern": "4D 5A", "addr": "0x7ff6b3a91000", "preview_hex": "4d5a900003000000" }
    ],
    "strings": [
      { "addr": "0x7ffde1234000", "text": "https://example.com" }
    ]
  }
}
```

## Output notes

* Addresses are hex virtual addresses inside the target process.
* `preview_hex` shows up to 16 bytes starting at the match.

## Permissions & safety

* Needs `PROCESS_VM_READ`. If you get `OpenProcess failed`, run your shell **as Administrator** or target a process you own.
* Scans only readable, committed memory (skips `PAGE_GUARD`/`PAGE_NOACCESS`). No process modification.

## Limitations

* Windows‑only. No kernel‑mode visibility (e.g., hidden driver regions won’t be seen).
* Regex‑like patterns: heavy patterns on huge processes may cost CPU; tune `--live` interval.
* Point‑in‑time scanner: fast‑changing buffers may be missed between intervals.

## Roadmap (nice‑to‑have)

* Dump surrounding memory for each hit to a file.
* Page protection filters (e.g., only `RX` or `RW`).
* YARA on live pages.

## License

MIT. For defensive/educational use.

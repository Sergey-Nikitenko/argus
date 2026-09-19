# Argus 🛡️

A Windows **process-creation watchdog** that watches → scores → decides → responds.

Argus tails process-creation events (Windows Security `4688` and/or Sysmon
`Event ID 1`), scores each spawn with heuristics, and — when you opt in —
auto-quarantines suspicious binaries (move, never delete) and kills the process
tree. It also detects **watcher-pairs** (dual-process watchdog malware).

Built on a clean split:

| Layer | Module | Notes |
|---|---|---|
| Event model + parsers | `argus/events.py` | 4688 + Sysmon 1 → one `ProcessEvent` |
| Scoring | `argus/score.py` | pure, deterministic heuristics |
| Watcher detection | `argus/watcher.py` | respawn storms + mutual spawn |
| Decision + response | `argus/engine.py` | allow / flag / quarantine |
| Quarantine + kill | `argus/quarantine.py` | move + JSONL manifest, `taskkill /T /F` |
| VirusTotal | `argus/verdict.py` | optional SHA256 reputation |
| CLI | `run.py` | `--once` / `--watch` / `--act` |

## Run

```powershell
# Dry-run (safe — report only)
py run.py --once

# Act for real (quarantine + kill high scorers)
py run.py --once --act

# Continuous, with VirusTotal lookups
py run.py --watch --interval 60 --act --vt-api-key YOUR_KEY
```

Environment overrides: `ARGUS_FLAG_THRESHOLD`, `ARGUS_KILL_THRESHOLD`,
`ARGUS_QUARANTINE_DIR`, `ARGUS_MANIFEST`, `ARGUS_VT_API_KEY`, `ARGUS_DRY_RUN=0`.

Defaults: `flag` at score ≥ 40, `quarantine` at score ≥ 70, dry-run ON.

## Test

```powershell
py -m unittest discover -s tests -t .
```

## Prerequisites

- **4688 events** require Windows audit policy "Process Creation" (auditpol or
  Group Policy). Sysmon gives richer events (`Image`, `Hashes`, `IntegrityLevel`)
  if installed, but is optional — Argus works on either.
- Running `--act` requires an elevated shell (it writes to `ProgramData` and
  kills processes).

## Design note

The scoring/decision/watcher logic is **pure** (no I/O) so it's fully unit
tested. All side effects live behind small functions that the tests mock, so a
passing test suite means the *decisions* are correct even though no real process
is touched during testing.

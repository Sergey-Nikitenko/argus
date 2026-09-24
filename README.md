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
| Behavioral signature | `argus/signature.py` | stable behavior → deterministic feature vector |
| Detection memory | `argus/memory.py` | two-tier episodic + semantic recall (cosine + decay) |
| Lineage graph | `argus/graph.py` | cross-session parent→child edges (novel-edge signal) |
| Sysmon installer | `argus/sysmon.py` | bundled config + install/status (Event 1 + 3) |
| CLI | `run.py` | `--once` / `--watch` / `--act` |

## Memory — watch, then remember

Argus keeps a two-tier memory so every alert isn't judged in isolation:

* **Episodic** (short-term): every flagged incident and its model verdict.
* **Semantic** (long-term): only **analyst-verified** verdicts — the "benign
  baseline" and "known incident" ground truth. Promotion is gated, so a
  model-only or `UNCERTAIN` verdict never poisons the baseline.

When an alert crosses the kill threshold, Argus abstracts it into a stable
**behavioral signature** (techniques + structure, not the raw command line),
retrieves the top-k similar past incidents, injects them into the local model's
prompt as *Historical Context*, and ingests the new outcome back into memory with
time-decay. A **lineage graph** also remembers every parent→child spawn across
sessions and flags **novel** relationships as a deviation from the learned
baseline.

The dashboard lets an analyst click **✓ benign (FP)** / **✗ malicious (TP)** on any
detection to promote that pattern to long-term memory.

## Run

```powershell
# Dry-run (safe — report only)
py run.py --once

# Act for real (quarantine + kill high scorers)
py run.py --once --act

# Continuous, with VirusTotal lookups
py run.py --watch --interval 60 --act --vt-api-key YOUR_KEY
```

Double-clicking the built `dist\Argus.exe` (or running it with no arguments)
opens the command-center dashboard in your browser and keeps running — that's
the friendly default for launching from Explorer.


Environment overrides: `ARGUS_FLAG_THRESHOLD`, `ARGUS_KILL_THRESHOLD`,
`ARGUS_QUARANTINE_DIR`, `ARGUS_MANIFEST`, `ARGUS_VT_API_KEY`, `ARGUS_DRY_RUN=0`.

Defaults: `flag` at score ≥ 40, `quarantine` at score ≥ 70, dry-run ON.

## Test

```powershell
py -m unittest discover -s tests -t .
```

## Sysmon (Event 1 + Event 3)

Sysmon is optional but unlocks Argus's richest telemetry — full command lines,
`Hashes`, `IntegrityLevel` (Event ID 1), and process→endpoint edges (Event ID 3)
that populate the lineage graph and `campaign()` / `blast_radius()` analysis.
Argus ships a canonical config (`argus/sysmon.py`) that enables exactly those
two events with **no exclusions**, so the graph is fully populated.

```powershell
# 1. Download Sysmon (Sysinternals): https://learn.microsoft.com/sysinternals/downloads/sysmon
# 2. Dump the bundled config (optional — install writes it automatically):
py run.py --sysmon-config sysmon-config.xml

# 3. Install (elevated shell required — loads the SysmonDrv kernel driver):
py run.py --install-sysmon C:\path\to\Sysmon64.exe

# 4. Verify:
py run.py --sysmon-status

# Later: reload a changed config / uninstall (both elevated):
py run.py --update-sysmon-config C:\path\to\Sysmon64.exe
py run.py --uninstall-sysmon C:\path\to\Sysmon64.exe
```

`--install-sysmon` and `--update-sysmon-config` write the bundled config to
`sysmon-config.xml` (override with `--sysmon-config-path`) when it doesn't
already exist, then pass it to Sysmon.

## Prerequisites

- **4688 events** require Windows audit policy "Process Creation" (auditpol or
  Group Policy). Sysmon gives richer events (`Image`, `Hashes`, `IntegrityLevel`)
  if installed, but is optional — Argus works on either.
- Running `--act` requires an elevated shell (it writes to `ProgramData` and
  kills processes). Installing/updating Sysmon also requires elevation.

## Design note

The scoring/decision/watcher logic is **pure** (no I/O) so it's fully unit
tested. All side effects live behind small functions that the tests mock, so a
passing test suite means the *decisions* are correct even though no real process
is touched during testing.

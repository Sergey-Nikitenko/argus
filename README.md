# Argus 🛡️

A Windows **EDR** with **hybrid local/cloud AI adjudication** and a **malware
detonation sandbox**. Argus watches process-creation events, scores each spawn
with deterministic heuristics, and routes high-risk threats to an AI model —
local or cloud — that judges them before any containment happens.

## AI integration — local + cloud models

Argus is built around a hybrid pipeline: deterministic rules do the fast
flagging, an AI model does the judgment, and only AI-confirmed threats are
auto-contained.

- **Local models** — Ollama (`localhost:11434`) or LM Studio (`localhost:1234`),
  any OpenAI-compatible endpoint. The dashboard has an AI selector that persists
  your choice.
- **Cloud models** — any OpenAI-compatible API:
  `py run.py --llm-model <model> --llm-url <url> --llm-api-key <key>`.
- **One-click provisioning** — Argus can download + install Ollama and pull a
  model for you (`argus/llm_provision.py`).
- **Fail-safe** — an absent, slow, or unsure model returns `UNCERTAIN`, and Argus
  never kills on uncertainty.
- **Agentic mode** — `--agent` gives the model investigation tools (function
  calling) so it can research a detection before judging.

The loop: **heuristics flag → AI adjudicates (MALICIOUS / BENIGN / UNCERTAIN) →
quarantine/kill only what the model confirms.**

## Malware detonation sandbox (CAPE/Cuckoo-style)

A five-stage pipeline detonates a sample in an isolated chamber and feeds the
result back to the AI dissection stage:

1. **Host orchestrator** — KVM/libvirt VM lifecycle (revert → boot → inject →
   harvest → revert).
2. **Guest detonation** — an instrumented Windows guest (Sysmon) + a silent agent
   that simulates a user and runs the sample.
3. **Fake-internet sinkhole** — an isolated bridge with FakeDNS/INetSim; every
   domain resolves to the sink, so the sample believes it phoned home.
4. **Snapshot revert + dump** — hard-kill the guest, harvest Sysmon telemetry,
   revert to the clean snapshot.
5. **AI dissection** — score the process chain, trace the execution, and ask the
   local model for primary intent + mitigation steps.

Layered **kill-switches** (L1–L5: egress firewall, injection guard, device guard,
hypervisor guard, detonation timeout) pull the chamber dead the instant a
boundary is crossed. See `argus/sandbox/`.

## Core detection

| Layer | Module | Notes |
|---|---|---|
| Event model + parsers | `argus/events.py` | 4688 + Sysmon 1/3 → `ProcessEvent` / `NetworkEvent` |
| Scoring | `argus/score.py` | pure, deterministic heuristics over a hot-reloadable rule store |
| Watcher detection | `argus/watcher.py` | respawn storms + mutual spawn |
| Decision + response | `argus/engine.py` | allow / flag / propose / quarantine |
| Quarantine + kill | `argus/quarantine.py` | move (never delete) + JSONL manifest, `taskkill /T /F` |
| VirusTotal | `argus/verdict.py` | optional SHA256 reputation |
| Behavioral signature | `argus/signature.py` | stable behavior → deterministic feature vector |
| Detection memory | `argus/memory.py` | two-tier episodic + semantic recall (cosine + decay) |
| Lineage graph | `argus/graph.py` | cross-session parent→child edges (novel-edge signal) |
| Rule generation | `argus/rulegen.py` / `argus/rules.py` | auto-draft Sigma rules from novel detections |
| Sysmon installer | `argus/sysmon.py` | bundled config + install/status (Event 1 + 3) |
| CLI | `run.py` | `--once` / `--watch` / `--act` / `--sandbox` / `--replay` |

## Memory — watch, then remember

Argus keeps a two-tier memory so every alert isn't judged in isolation:

- **Episodic** (short-term): every flagged incident and its model verdict.
- **Semantic** (long-term): only **analyst-verified** verdicts — the "benign
  baseline" and "known incident" ground truth. Promotion is gated, so a
  model-only or `UNCERTAIN` verdict never poisons the baseline.

When an alert crosses the kill threshold, Argus abstracts it into a stable
**behavioral signature** (techniques + structure, not the raw command line),
retrieves the top-k similar past incidents, injects them into the local model's
prompt as *Historical Context*, and ingests the new outcome back into memory with
time-decay. A **lineage graph** remembers every parent→child spawn across sessions
and flags **novel** relationships as a deviation from the learned baseline.

## Run

```powershell
# Dry-run (safe — report only)
py run.py --once

# Act for real, with a local AI model judging would-be kills (default: on)
py run.py --once --act

# Continuous, with VirusTotal + AI
py run.py --watch --interval 60 --act --vt-api-key YOUR_KEY

# Agentic mode — the model gets investigation tools
py run.py --watch --agent

# Disable the AI layer
py run.py --once --no-llm

# Replay a JSONL bank of events (safe testing)
py run.py --replay events.jsonl
```

Double-clicking the built `dist\Argus.exe` (or running with no arguments) opens
the command-center dashboard and keeps running.

Environment overrides: `ARGUS_FLAG_THRESHOLD`, `ARGUS_KILL_THRESHOLD`,
`ARGUS_QUARANTINE_DIR`, `ARGUS_VT_API_KEY`, `ARGUS_LLM_API_KEY`, `ARGUS_DRY_RUN=0`.

Defaults: `flag` at score ≥ 40, `quarantine` at score ≥ 85, dry-run ON.

## Test

```powershell
py -m pytest tests/ -q
```

## Sysmon (Event 1 + Event 3)

Sysmon is optional but unlocks Argus's richest telemetry — full command lines,
`Hashes`, `IntegrityLevel` (Event ID 1), and process→endpoint edges (Event ID 3)
that populate the lineage graph and campaign/blast-radius analysis. Argus ships a
canonical config (`argus/sysmon.py`) that enables exactly those events with no
exclusions.

```powershell
# 1. Download Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon
py run.py --sysmon-config sysmon-config.xml      # dump the bundled config
py run.py --install-sysmon C:\path\to\Sysmon64.exe   # install (elevated)
py run.py --sysmon-status                        # verify
```

## Prerequisites

- **4688 events** require Windows audit policy "Process Creation" (auditpol or
  Group Policy). Sysmon is optional but recommended.
- Running `--act` requires an elevated shell. Installing Sysmon also requires
  elevation.
- The AI layer needs a reachable OpenAI-compatible endpoint (Ollama, LM Studio,
  or a cloud API).

## Design note

The scoring/decision/watcher logic is **pure** (no I/O) and fully unit-tested.
All side effects live behind small functions the tests mock, so a passing suite
means the *decisions* are correct even though no real process is touched.

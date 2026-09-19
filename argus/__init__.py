"""Argus — a Windows process-creation watchdog.

Argus watches process-creation events (Windows Security 4688 and/or Sysmon
Event ID 1), scores each one with a set of heuristics, and can flag or
auto-quarantine suspicious spawns. The decision logic is pure and unit-tested;
the side-effecting parts (event reads, file moves, process kills) are thin
adapters so they can be swapped or mocked.
"""

__version__ = "0.1.0"

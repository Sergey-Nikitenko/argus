"""The silent guest agent — injected into the chamber BEFORE the clean snapshot.

Malware frequently waits for a human: an Office macro that needs "Enable
Content", a document that needs a click, a payload that sleeps until the mouse
moves. This agent runs inside the guest and, on demand, simulates that user so
the payload proceeds to detonate. It is a stdlib-only script, self-contained,
and its only job is to make the chamber look inhabited:

  1. simulate user activity (mouse move + clicks via ctypes, light scrolling)
  2. auto-enable Office "Enable Content" where wired
  3. watch a drop folder, then execute the injected sample
  4. write a "detonated" marker so the host knows the run finished

``guest_agent_source`` returns the script text (pure); ``write_guest_agent``
drops it to disk for injection into the guest image.
"""
from __future__ import annotations

from pathlib import Path

_DEFAULT_DROP_DIR = r"C:\Users\Public\argus-drop"


def guest_agent_source(
    drop_dir: str = _DEFAULT_DROP_DIR,
    poll_seconds: int = 2,
    user_sim: bool = True,
    auto_enable: bool = True,
) -> str:
    """The guest-agent Python source (stdlib-only, runs inside the Windows guest)."""
    sim_block = _SIM_BLOCK if user_sim else "# user simulation disabled"
    enable_block = _ENABLE_BLOCK if auto_enable else "# auto-enable disabled"
    return _AGENT_TEMPLATE.format(
        drop_dir=drop_dir, poll_seconds=poll_seconds,
        sim_block=sim_block, enable_block=enable_block,
    )


def write_guest_agent(path, **kwargs) -> Path:
    p = Path(path)
    p.write_text(guest_agent_source(**kwargs), encoding="utf-8")
    return p


_SIM_BLOCK = '''def simulate_user():
    """Move the mouse + click a couple times so interaction-gated payloads fire."""
    try:
        import ctypes, random, time
        user32 = ctypes.windll.user32
        SW, SH = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
        for _ in range(5):
            user32.SetCursorPos(random.randint(0, SW), random.randint(0, SH))
            time.sleep(0.3)
        for _ in range(2):
            user32.mouse_event(0x0002, 0, 0, 0, 0)  # left down
            user32.mouse_event(0x0004, 0, 0, 0, 0)  # left up
            time.sleep(0.2)
    except Exception:
        pass  # activity is best-effort; never block detonation
'''

_ENABLE_BLOCK = '''def auto_enable_content():
    """Best-effort: many Office payloads need the user to click 'Enable Content'.
    Real deployments drive this via UI automation (pywinauto / a VBA shim); the
    stdlib agent can only note it and let the macro timer path take over."""
    pass
'''

_AGENT_TEMPLATE = '''"""Argus sandbox guest agent — runs INSIDE the detonation chamber."""
import os
import subprocess
import sys
import time
from pathlib import Path

DROP_DIR = r"{drop_dir}"
POLL_SECONDS = {poll_seconds}
MARKER = os.path.join(DROP_DIR, "detonated.marker")

{sim_block}

{enable_block}


def main():
    try:
        os.makedirs(DROP_DIR, exist_ok=True)
    except Exception:
        pass
    try:
        simulate_user()
    except Exception:
        pass
    try:
        auto_enable_content()
    except Exception:
        pass

    deadline = time.time() + 180
    detonated = False
    while time.time() < deadline:
        try:
            samples = sorted(
                p for p in Path(DROP_DIR).glob("*")
                if p.suffix.lower() in (".exe", ".docm", ".doc", ".xlsm", ".pdf",
                                        ".js", ".vbs", ".ps1", ".bat", ".scr", ".msi")
            )
        except Exception:
            samples = []
        if samples:
            for s in samples:
                try:
                    if s.suffix.lower() == ".ps1":
                        subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Bypass",
                                          "-File", str(s)])
                    else:
                        os.startfile(str(s))
                    detonated = True
                except Exception:
                    pass
            try:
                Path(MARKER).write_text("detonated", encoding="utf-8")
            except Exception:
                pass
            if detonated:
                break
        time.sleep(POLL_SECONDS)

    # keep the chamber alive long enough for the payload to do its work
    time.sleep(120)
    return 0 if detonated else 2


if __name__ == "__main__":
    sys.exit(main())
'''

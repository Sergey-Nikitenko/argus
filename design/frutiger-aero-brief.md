# Argus Dashboard — Frutiger Aero Rebuild (Shared Context Bubble)

> Inherited by every subagent working on this rebuild. Read this first, then your task file.

## Mission

Rebuild `C:\workspace\argus\dashboard\index.html` so it looks and feels like a
genuine **2000s-era UI** — specifically **Frutiger Aero glass** (2005–2013), the
bright, glossy, airy aesthetic of Windows Vista/7, early OS X, and Web 2.0.

The current build is "dark neon glassmorphism" — a 2020s look. It is WRONG for the
era and must be replaced, not patched.

## Hard constraints (do not break)

- **Single file** `dashboard/index.html` (inline CSS + JS), served by Argus's
  stdlib-only HTTP server (`argus/server.py`). No build step, no CDN, no new
  dependencies, no framework.
- **Preserve every feature and data flow:**
  - GET endpoints: `/api/status`, `/api/detections`, `/api/quarantine`,
    `/api/watcher`, `/api/memory`, `/api/graph`, `/api/rules`.
  - POST endpoints: `/api/restore`, `/api/adjudicate`, `/api/approve`,
    `/api/rules/approve`.
  - Tabbed detail panes: Memory / Lineage / Rules / Vault / Watcher.
  - The reskin selector (8 skins) — keep the mechanism, re-theme it 2000s.
  - FP/TP feedback buttons + toast + "verified" badge.
  - Approve containment, Restore, rule-approve.
  - Stat tiles, detection feed, equalizer visualizer, tilt, starfield
    (may be replaced with era-appropriate equivalents).
- **Do NOT touch the Python backend** (`argus/*.py`, `run.py`) — 90 tests green.
  Only `dashboard/index.html` changes.
- Rebuild: `py -m PyInstaller --noconfirm --clean Argus.spec` (dashboard bundled
  via `datas=[('dashboard','dashboard')]`). Exe output: `dist\Argus.exe`.

## Research findings so far (how 2000s UI was ACTUALLY built)

1. **Asset-driven, not CSS-driven.** Winamp `.wsz` = ZIP of bitmap sprite strips
   (`main.bmp`, `cbuttons.bmp`, `titlebar.bmp`, `eqmain.bmp`, `numbers.bmp`, …)
   + `regions.txt` (non-rectangular window mask) + `viscolor.txt`. WMP `.wms` =
   ZIP of images + XML control mapping (`mappingImage`/`hoverImage`/`downImage`)
   + JScript. XP Luna `.msstyles` = compiled bitmap strips + **sizing margins**
   (9-slice scaling — the ancestor of CSS `border-image`).
2. **The visual grammar:** bright, light, airy — aqua/cyan, sky blue, soft green,
   white, translucent glass. NOT dark neon.
3. **Six techniques:** (a) 9-slice scaling, (b) sprite strips, (c) non-rectangular
   regions, (d) specular highlight (white top-half gradient + 1px top edge),
   (e) bevel (light top-left / dark bottom-right), (f) skeuomorphic materials
   (glass, metal, gel, water).
4. **Frutiger Aero signature:** glass, water, aurora, bubbles, gloss, light
   blue/green/white, optimism, "fresh water for the brain."

## Target look (acceptance bar)

Unmistakably Frutiger Aero: bright glass surfaces with white specular gloss,
rounded beveled frames, frosted translucency, aurora + bubble/water motifs,
light aqua/sky palette, soft shadows. While keeping every Argus feature working.

ALSO fold in **Windows Media Player skin aesthetics** as generative context (the
user explicitly wants WMP skins' look): metallic chrome beveled window frames
(brushed aluminum + polished chrome gradients), glossy transport buttons, LCD
readouts with a teal glow, the WMP 9/10/11 "Corona" chrome look. Use WMP-skin
descriptions in every image-generation prompt and in the build spec.

## Work in progress (subagents append their specs here)

- `design/spec-frutiger-aero.md` — palette + material/gloss CSS recipes.
- `design/spec-skin-construction.md` — Winamp/WMP → web recreation techniques.

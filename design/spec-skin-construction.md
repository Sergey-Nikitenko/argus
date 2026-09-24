# Argus Dashboard — Skin Construction Spec (Winamp `.wsz` / WMP `.wms` → single-file web)

> Companion to `design/spec-frutiger-aero.md` (palette + gloss recipes). This file
> covers **how 2000s media-player skins were BUILT** and translates each construction
> technique into concrete HTML/CSS/JS for `dashboard/index.html`.
>
> Hard constraints inherited from the brief: **single file**, inline CSS+JS, no build
> step, no CDN, no new deps, every API/feature preserved. This spec therefore leans on
> (a) inline SVG **data-URI** asset strips and (b) pure-CSS bevel/gloss — the two
> techniques that stay "asset-driven" without shipping external files.

---

## 0. The one-line thesis

A 2000s media-player skin is **not a set of CSS widgets**. It is a **flat bitmap
atlas** (a ZIP of `.bmp`/`.png` strips) plus a **text file** that says where each
button/slider/state lives in that atlas (`regions.txt`, the WMP XML, or msstyles
sizing margins). The authentic web recreation is therefore: *build the atlas once,
then position into it with `background-position`, scale its frame with
`border-image`, and cut the window shape with `clip-path`.*

Everything below is that thesis, unrolled per format, then as copy-paste CSS.

---

## 1. Winamp classic skin anatomy (`.wsz`)

A `.wsz` file is literally a **ZIP archive renamed**. Inside:

- **Bitmap sprite strips** — every UI surface is a region inside a fixed-size BMP.
- **`region.txt`** — the non-rectangular window mask (opaque-add / transparent-cut).
- **`viscolor.txt`** — 24 RGB colors for the spectrum analyzer / oscilloscope.
- Optional: `pledit.txt` (playlist colors + column layout), `gen.bmp`/`genex.bmp`
  (general-purpose window), cursors, `readme.txt`.

### 1.1 The bitmap atlas — fixed regions, fixed pixel sizes

Winamp 2.x draws the skin by **blitting a hard-coded rectangle out of each BMP**.
The base skin dimensions are the contract (values from the classic skin spec; a few
drift ±1px between Winamp 2.9 / 5.x — treat the *principle* as load-bearing, the
exact px as reference):

| File            | Size (px)   | What each region is                                            |
|-----------------|-------------|----------------------------------------------------------------|
| `main.bmp`      | 275 × 116   | Main window: titlebar strip, LCD display well, volume/balance/seek slider tracks + backgrounds |
| `cbuttons.bmp`  | 161 × 18    | **7 transport buttons side-by-side**, each 23 × 18: prev · play · pause · stop · next · eject · open |
| `titlebar.bmp`  | 275 × 27    | Titlebar strip; window buttons (close/min/winshade/on-off) drawn from fixed x-offsets |
| `shufrep.bmp`   | 92 × 12     | Shuffle + repeat toggles; each toggle is 2–3 state frames side-by-side |
| `volume.bmp`    | 68 × 420    | **Slider filmstrip**: 28 frames × 68 × 15 — the thumb pre-rendered at 28 discrete positions |
| `balance.bmp`   | 38 × 420    | Balance slider filmstrip: 28 frames × 38 × 15 |
| `eqmain.bmp`    | 275 × 116   | Equalizer window: band sliders, preamp, on/auto/presets |
| `pledit.bmp`    | 275 × 116   | Playlist editor window: list background + scrollbar wells |
| `numbers.bmp`   | 9 × 13      | **One digit glyph** (the LCD counter draws 0–9 + `-` from this cell) |
| `nums_ex.bmp`   | 90 × 13     | Alternative: 10 digit glyphs laid out horizontally (10 × 9 wide each) |
| `mb.bmp`        | 25 × 9      | Minibrowser / media-info window buttons |
| `text.bmp`      | ~251 × 14   | Scrolling "ticker" text strip (marquee text) |

Key construction facts that map 1:1 to CSS:

1. **Buttons are state-frames in one strip.** A button never has "a hover color";
   it has *N pre-rendered frames* laid out side-by-side. Hover/press just changes
   which frame is shown. `cbuttons.bmp` = 7 buttons × 23px = 161px wide; each
   button's own hover/press variants, if any, multiply its width.
2. **Sliders are discrete, not continuous.** Winamp does **not** interpolate a
   thumb along a track. `volume.bmp` is a vertical strip of **28 pre-rendered
   frames**, each showing the thumb at one of 28 positions; moving the slider swaps
   the frame. (This is why Winamp sliders feel "clicky".) The CSS equivalent is
   `background-position-y: calc(var(--val) * -frameH)` over a 28-frame strip.
3. **Digits are glyph cells.** The LCD timer is assembled glyph-by-glyph from
   `numbers.bmp` (one 9×13 cell) — the ancestor of an icon font / a
   `background-position` digit spritesheet.
4. **The window is rectangular data + a mask.** The BMPs are rectangles; the
   *shape* is applied by `region.txt` at runtime.

### 1.2 `region.txt` — the non-rectangular window mask

Winamp's window is cut from the rectangular bitmap by a region list. The format
(section per window state, `NumPoints` then coordinate lines):

```
[normal]               ; main window, normal size
NumPoints = 4
0, 0, 275, 116, 1      ; x, y, w, h, scale  → ADD this rectangle
0, 0, 275, 116, 0      ; scale 0            → SUBTRACT (punch a hole)
...
[windowshade]          ; rolled-up titlebar
NumPoints = 2
0, 0, 275, 14, 1
```

Rules:
- `NumPoints` = how many entry lines follow (despite the name, an entry is a rect).
- Rectangle form: `x, y, width, height, scale`. Point form: `x, y, scale`.
- `scale = 1` **adds** (opaque), `scale = 0` **subtracts** (transparent cutout).
- Entries are evaluated in order; the region starts empty. Rounded corners are
  faked by subtracting corner rects, arbitrary silhouettes by stacking many rects.

**CSS equivalents** (listed best→least faithful):

| Winamp | Web |
|--------|-----|
| Subtract corner rects for rounded chrome | `border-radius` (exact same math, built-in) |
| Arbitrary silhouette | `clip-path: polygon(...)` / `path(...)` |
| Soft alpha holes (antialiased) | `mask-image: radial-gradient(...)` |
| Transparent window behind the chrome | `body { background: transparent }` + framed shell |

> Note: the dashboard lives **inside a browser viewport**, not a top-level window,
> so we don't need `regions.txt` fidelity — we want the *look* of a shaped chrome
> device. `border-radius` + a chrome frame + a `clip-path` on the outer shell is
> the correct translation.

### 1.3 `viscolor.txt` — the visualizer palette

Exactly **24 lines**, each `R,G,B` (0–255), consumed by the spectrum analyzer and
oscilloscope. The analyzer walks/cycles these colors across its bands.

```
24, 33, 41
...
```

**Web translation:** a 24-entry JS palette array that drives the equalizer bars and
the spectrum canvas. The existing `--teal/--gold` accent pair is the modern
shorthand; the authentic move is a *real* 24-color ramp (dark→bright→white, then a
hot highlight) that the visualizer indexes by band.

---

## 2. Windows Media Player skin anatomy (`.wms`)

A `.wms` is also a **ZIP**: image files (`.bmp`/`.png`/`.jpg`/`.gif`) + a **skin
definition XML** (`*.xml`) + optional **JScript** (`.js`).

### 2.1 Images + XML control mapping (the key difference from Winamp)

WMP does **not** use one giant sprite strip per window. It uses **separate image
files per control, per state**, and the XML *declares* which file is which state:

```xml
<THEME>
  <VIEW clippingColor="#00FF00" backgroundImage="back.png"
        titleBar="false">
    <BUTTONGROUP mappingImage="btn_play.png"
                 hoverImage="btn_play_hover.png"
                 downImage="btn_play_down.png"
                 sticky="false">
      <BUTTON ... />
    </BUTTONGROUP>
  </VIEW>
</THEME>
```

State attributes, exactly as they map to web:

| WMP attribute   | Web equivalent                          |
|-----------------|------------------------------------------|
| `mappingImage`  | default sprite frame / `background`      |
| `hoverImage`    | `:hover` state                           |
| `downImage`     | `:active` state                          |
| `disabledImage` | `:disabled` state                        |
| `clippingColor` | transparency key → `mask`/`clip-path`    |
| `backgroundImage` | `background-image` on the view        |

Other elements (all have direct web twins):
- **`<VIEW>`** — a layer/surface (like a positioned `div`), stackable, each with
  its own `clippingColor` (transparency).
- **`<BUTTON>` / `<BUTTONGROUP>`** — hit regions with state images + optional
  `onclick` JScript; `sticky` = toggle (pressed latch).
- **`<TEXT>`** — a text label; **`<EDIT>`** — editable field (input).
- **`<SLIDER>`** — `backgroundImage` (track) + `thumbImage`, fires `onpositionchange`.
- **`<PROGRESS>`** — playback position bar (the "seek" bar).
- **`<PLAYER>`**, **`<VIDEO>`**, **`<VISUALIZATION>`**, **`<ART>`** — embedded
  media surfaces; for Argus, the "visualization" region is where the equalizer/
  spectrum canvas goes.
- **`<TIMER>`** — fires a JScript tick (the 2000s answer to `setInterval`).

### 2.2 JScript — behavior rides the skin, not the app

WMP skins carry `.js` files with handlers like:

```js
function PlayButton_onclick() { player.controls.play(); }
function VolSlider_onpositionchange() { player.settings.volume = VolSlider.value; }
```

**Web translation:** this is *exactly* the dashboard's existing pattern —
`el.onclick = async () => fetch('/api/...')`. The 2000s-authentic framing is to
name handlers `X_onclick` and attach them per-control, mirroring WMP's convention,
while keeping the same `fetch` bodies.

### 2.3 What to steal from WMP vs Winamp

- Steal **WMP's** *state-per-control* mental model for the modern part (it's what
  CSS `:hover/:active` already gives us).
- Steal **Winamp's** *sprite atlas + discrete slider filmstrip + glyph cells* for
  the authentic look (it's what makes it *feel* like a 2000s device, not a website).

---

## 3. 9-slice / "sizing margins" → CSS `border-image`

### 3.1 What it is

XP Luna `.msstyles` (and Vista Aero) store each frame as a bitmap plus **sizing
margins** — four numbers (top/right/bottom/left) that declare which pixels are
**fixed corners** and which **stretch**. The center is either filled or left as the
content well. This is "9-slice scaling": 4 corners (unscaled) + 4 edges (stretched
one axis) + 1 center (stretched both / optional).

Winamp does *not* 9-slice (its windows are fixed-size bitmaps); **WMP and msstyles
do**. For a resizable web dashboard, 9-slice is what lets a chrome frame look
crisp at any viewport size — so it's the single most important technique in this
spec.

### 3.2 The CSS twin

`border-image` is literally 9-slice. One property covers source + slices + repeat:

```
border-image: <source> <slice>/<width>/<outset> <repeat>;
```

- `<slice>` — 1–4 numbers = the sizing margins, measured **inward from the edge**.
  Units: `px`/`%`/unitless number (number = px for raster, coordinate for SVG).
- `fill` keyword — draw the center too (msstyles "fill content").
- `<repeat>` — `stretch` (default, the authentic msstyles behavior), `round`
  (tile without clipping), `repeat` (tile, may clip).

### 3.3 Recipe A — the pragmatic CSS-only chrome (recommended default)

For a single-file dashboard with no external assets, a beveled metallic frame is
*itself* a 9-slice made of CSS: `border` gives the 4 edges, `border-radius` gives
the corners, `background` fills the center. No `border-image` needed.

```css
/* Glass + chrome frame, pure CSS (a "generated 9-slice") */
.pane {
  position: relative;
  border-radius: 16px;                                   /* the 4 "corners" */
  border: 1px solid rgba(255,255,255,.55);               /* top edge highlight */
  border-bottom-color: rgba(20,50,80,.55);               /* bottom edge shadow */
  background:
    /* center fill — frosted glass */
    linear-gradient(165deg, rgba(255,255,255,.28), rgba(255,255,255,.06) 45%, rgba(190,225,255,.10)),
    rgba(210, 235, 255, .18);
  /* bevel: light top-left, dark bottom-right, via inset shadows (the 4 edges) */
  box-shadow:
    inset 0 1px 0 rgba(255,255,255,.8),                  /* top bevel light */
    inset 1px 0 0 rgba(255,255,255,.35),                 /* left bevel light */
    inset 0 -1px 0 rgba(30,60,95,.35),                   /* bottom bevel dark */
    inset -1px 0 0 rgba(30,60,95,.20),                   /* right bevel dark */
    0 12px 32px -14px rgba(40,90,140,.45);               /* drop shadow */
  backdrop-filter: blur(12px) saturate(1.4);             /* frosted translucency */
}
/* Specular gloss cap: white top-half gradient + 1px top edge */
.pane::after {
  content: "";
  position: absolute; inset: 0; border-radius: inherit; pointer-events: none;
  background:
    radial-gradient(120% 55% at 50% -8%, rgba(255,255,255,.75), rgba(255,255,255,.12) 46%, transparent 60%);
}
```

### 3.4 Recipe B — the authentic `border-image` 9-slice (asset-driven)

When you *do* want a real bitmap frame (the closest thing to shipping an msstyles
frame in a single file), embed it as an inline SVG data-URI and slice it:

```css
.chrome-frame {
  border: 14px solid transparent;                /* reserve the gutter */
  border-image-source: url("data:image/svg+xml,...");   /* the frame atlas */
  border-image-slice: 14 14 14 14 fill;          /* sizing margins = 14px frame */
  border-image-width: 14px;
  border-image-repeat: stretch;                  /* authentic msstyles behavior */
  border-image-outset: 0;
}
```

Example frame atlas as inline SVG (a beveled chrome rectangle; the 14px band around
the edge is the slice that gets 9-sliced). URL-encode `#`→`%23`, `<`→`%3C`, etc.
when inlining, or keep it on one readable line in dev:

```html
<!-- frame.svg: 44x44 source, 14px chrome band, glass center -->
<svg xmlns="http://www.w3.org/2000/svg" width="44" height="44">
  <defs>
    <linearGradient id="m" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#ffffff"/>
      <stop offset=".5" stop-color="#bcd6ec"/>
      <stop offset=".5" stop-color="#9db9d4"/>
      <stop offset="1" stop-color="#6e8db0"/>
    </linearGradient>
  </defs>
  <rect x="1" y="1" width="42" height="42" rx="10" fill="url(#m)" stroke="#ffffff"/>
  <rect x="4" y="4" width="36" height="36" rx="7" fill="#dff1ff" opacity=".5"/>
</svg>
```

With `slice: 14`, the corners (the rounded `rx=10` chrome) stay put and the straight
edges stretch — the frame stays crisp at 320px or 1920px wide, exactly like a Luna
theme scales.

> **Why Recipe A is the default:** it needs zero data-URI encoding and renders
> retina-crisp at any size; `border-image` raster slices visibly pixelate when the
> browser stretches a low-res PNG. Use Recipe B for a literal "shipped frame" feel,
> and prefer an **SVG** source (SVG `border-image-slice` cuts by coordinate, so it
> stays sharp).

---

## 4. Web recreation: the five signature techniques

### 4.1 Sprite-strip buttons (single image, all states, `background-position`)

Winamp's `cbuttons.bmp` = N states laid out horizontally in one image. CSS twin:

```css
/* one strip: [normal][hover][down] = 3 × 23px wide, 18px tall → 69×18 atlas */
.cbtn {
  width: 23px; height: 18px;
  background: url("data:image/svg+xml,...") no-repeat;   /* the single strip */
  background-position: 0 0;                              /* normal frame */
  border: 0; cursor: pointer;
}
.cbtn:hover  { background-position: -23px 0; }           /* hover frame  */
.cbtn:active { background-position: -46px 0; }           /* down frame   */
```

Strip-source example (a glossy aqua "play" button, 3 states, generated once):

```html
<!-- cbtn_play.svg : 69x18, three 23x18 frames -->
<svg xmlns="http://www.w3.org/2000/svg" width="69" height="18" shape-rendering="crispEdges">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#eaf6ff"/><stop offset=".5" stop-color="#7fc4f0"/>
      <stop offset=".5" stop-color="#5aa6dc"/><stop offset="1" stop-color="#2f6f9f"/>
    </linearGradient>
  </defs>
  <!-- frame 0 : normal -->
  <g>
    <rect x="1" y="1" width="21" height="16" rx="3" fill="url(#g)" stroke="#1e4e78"/>
    <rect x="1" y="1" width="21" height="8"  rx="3" fill="#ffffff" opacity=".45"/>  <!-- specular cap -->
  </g>
  <!-- frame 1 : hover (brighter) → translate group +22 -->
  <g transform="translate(23,0)"> ...same but opacity .7 cap... </g>
  <!-- frame 2 : down (inverted bevel) → translate group +46 -->
  <g transform="translate(46,0)"> ...same but top edge dark, no cap... </g>
</svg>
```

General rules for the strip:
- One image, one `<svg>`/data-URI, **one HTTP-free asset**.
- Each state is a fixed-width cell; `:hover/:active` only changes
  `background-position` (a "state swap", never a re-render).
- Keep the strip horizontal (Winamp convention) — `background-position-x`.
- For a **slider filmstrip** (Winamp `volume.bmp`), rotate the idea 90°: a
  **vertical** strip of 28 thumb frames, selected by `--val`:

```css
/* 28 discrete thumb frames, each 68x15 → 68x420 vertical strip */
.vol-thumb {
  width: 68px; height: 15px;
  background: url("data:image/svg+xml,...") no-repeat;
  background-position-y: calc(var(--v) * -15px);   /* --v: 0..27 */
}
```

(Though for the dashboard, a continuous CSS slider is *fine* — the discrete
filmstrip is a visual flourish you can apply to the seek/progress bar only.)

### 4.2 Beveled metallic / chrome frame

The chrome look = a high-contrast vertical gradient (light→mid→mid→dark) + a 1px
light top edge + a 1px dark bottom edge. Two implementations:

```css
/* metal: hard stop at 50% gives the machined "chrome bar" look */
.chrome {
  background: linear-gradient(180deg,
    #f4f9ff 0%, #c6d9ec 48%, #8fb0cd 50%, #5f86ab 52%, #3c5f83 100%);
  border-top: 1px solid #ffffff;
  border-bottom: 1px solid #1c3854;
}
/* brushed variant: repeating hard stops (very 2000s car-stereo) */
.brushed {
  background: repeating-linear-gradient(180deg,
    #e8f1fa 0 2px, #c9dcee 2px 3px);
}
```

Bevel rule of thumb (Winamp used it everywhere): **light source top-left** →
`border-top/left` light, `border-bottom/right` dark; invert for the pressed
("down") state so a button visibly "travels".

### 4.3 Glossy specular caps on buttons

The Frutiger Aero "gel button" is a **specular highlight** — a white gradient that
dies out before the button's midpoint, plus a 1px white top edge:

```css
.gel-btn {
  border-radius: 8px;
  border: 1px solid rgba(255,255,255,.7);
  border-bottom-color: rgba(20,50,85,.55);
  background:
    radial-gradient(150% 120% at 50% -20%, rgba(255,255,255,.95), rgba(255,255,255,.15) 48%, transparent 60%),
    linear-gradient(180deg, #a8d6ff, #3f8fd0 60%, #27689e);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.9), 0 2px 6px rgba(30,70,110,.4);
  text-shadow: 0 1px 0 rgba(255,255,255,.6);
}
.gel-btn:active {
  background:
    radial-gradient(150% 120% at 50% -20%, rgba(255,255,255,.5), rgba(255,255,255,0) 45%),
    linear-gradient(180deg, #27689e, #3f8fd0 60%, #a8d6ff);   /* inverted: sunken */
  box-shadow: inset 0 2px 5px rgba(10,30,55,.5);              /* inner shadow = pressed */
}
```

### 4.4 LCD-style readouts

The Winamp display / WMP text is an **LCD**: dark green/blue well + inset shadow +
segmented mono digits + a faint scanline sheen.

```css
.lcd {
  font-family: "Cascadia Mono", "Lucida Console", Consolas, monospace;
  color: #9fffc4;                                   /* phosphor green */
  background:
    repeating-linear-gradient(0deg, rgba(255,255,255,.03) 0 1px, transparent 1px 3px),
    linear-gradient(180deg, #04121a, #072432);
  border: 1px solid #0a3146;
  border-radius: 6px;
  box-shadow: inset 0 2px 8px rgba(0,0,0,.8), inset 0 0 2px rgba(120,255,200,.25);
  text-shadow: 0 0 6px rgba(120,255,200,.5);
  letter-spacing: 2px;
}
/* 7-segment glyphs (numbers.bmp → CSS) */
.lcd .digit { width: 9px; height: 13px;
  background: url("data:image/svg+xml,...") no-repeat;   /* one glyph cell */
  background-position: calc(var(--d) * -9px) 0; }
```

### 4.5 Non-rectangular, chrome-framed "device" silhouette

Wrap the whole dashboard in a **shaped shell** that reads as one physical player:

```css
.shell {
  clip-path: polygon(
    24px 0, calc(100% - 24px) 0,          /* top edge with corner cuts */
    100% 24px, 100% calc(100% - 24px),
    calc(100% - 24px) 100%, 24px 100%,
    0 calc(100% - 24px), 0 24px
  );
  border-radius: 20px;                       /* combined w/ clip-path = rounded device */
}
```

`clip-path` is `region.txt`; `border-radius` is the "subtract corner rects"; the
chrome `border-image`/bevel is the frame; the glass `::after` is the glare. All four
stack on the single `.shell` element.

---

## 5. Recommended "command-center" layout (2000s media-player chassis)

Map Argus's existing panels onto a media-player body, top to bottom:

```
┌───────────────────────────────────────────────────────────────┐
│ TITLEBAR   ◣ ◢  ARGUS · command center        [iris ▼]  ● LIVE │  ← titlebar.bmp + window btns
├───────────────────────────────────────────────────────────────┤
│ MAIN DISPLAY (LCD)  ── now playing ≡ "What the watch sees"     │  ← main.bmp LCD well
│   scrolling detection ticker + headline stat + severity LEDs   │  ← text.bmp marquee
├───────────────────────────────────────────────────────────────┤
│ STAT TILES (8)  ≡ Winamp "shade mode" LCD counters             │  ← numbers.bmp glyphs
├───────────────────────────────────────────────────────────────┤
│ TRANSPORT  ⏮ ▶ ⏸ ⏹ ⏭ ⏏        VOL [▬▬▬───]  BAL [──▬▬──]     │  ← cbuttons + volume/balance strips
│   (approve / restore / adjudicate / rule-approve as transport) │
├───────────────────────────────────────────────────────────────┤
│ EQ / VISUALIZER strip (spectrum analyzer, 24 viscolor ramp)    │  ← eqmain.bmp + viscolor.txt
├──────────────────────────────┬────────────────────────────────┤
│ FEED (detections)            │  DETAIL PANEL (tabs)            │
│  ≡ playlist editor           │  Memory / Lineage / Rules /     │
│  columnar mono rows          │  Vault / Watcher                │
│                              │  ≡ pledit.bmp list             │
└──────────────────────────────┴────────────────────────────────┘
```

Concrete mapping table (existing element → media-player chassis):

| Argus element (current)      | 2000s skin role                         | Technique            |
|------------------------------|-----------------------------------------|----------------------|
| `.topbar` / `.brand`         | `titlebar.bmp` strip + window buttons   | chrome bar + gel caps|
| `#status` pill (LIVE/DRY)    | titlebar status LED                     | LCD LED + glow       |
| `.eq` in the topbar          | **promote to full EQ/spectrum strip**   | 24-color `viscolor` ramp |
| `.stats` (8 tiles)           | shade-mode LCD counters                 | `.lcd` + digit glyphs|
| `.skin-select`               | WMP "skin chooser" dropdown             | keep mechanism, gel style |
| detection feed `.det`        | **playlist editor list** (`pledit.bmp`) | mono rows + column headers |
| detail tabs (Memory/…/Watcher)| playlist columns / detail pane          | tab = playlist column |
| FP/TP + approve + restore buttons | **transport strip** (`cbuttons.bmp`)| sprite-strip states |
| flag/kill thresholds         | **volume/balance sliders**              | slider filmstrip     |
| starfield + nebula + scanline| **aurora/water Frutiger Aero backdrop** | soft radial gradients |

Priority order for the rebuild (what most moves the "is this Winamp or a website?"
needle first): **(1)** chrome/glass frame + specular gloss everywhere, **(2)** the
transport-strip sprite buttons, **(3)** the LCD readout treatment, **(4)** the EQ
visualizer with a 24-color ramp, **(5)** the shaped `.shell` clip-path.

---

## 6. Copy-paste starter kit (drop-in, no deps)

### 6.1 A complete sprite-strip transport button (SVG data-URI)

One button, three 32×24 states (normal/hover/down), gloss + bevel + a glyph:

```css
:root {
  --sprite-play: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='96' height='24'%3E%3Cdefs%3E%3ClinearGradient id='b' x1='0' y1='0' x2='0' y2='1'%3E%3Cstop offset='0' stop-color='%23eef8ff'/%3E%3Cstop offset='.5' stop-color='%237fc4f0'/%3E%3Cstop offset='.5' stop-color='%235aa6dc'/%3E%3Cstop offset='1' stop-color='%232f6f9f'/%3E%3C/linearGradient%3E%3C/defs%3E%3Cg%3E%3Crect x='1' y='1' width='30' height='22' rx='4' fill='url(%23b)' stroke='%231e4e78'/%3E%3Crect x='1' y='1' width='30' height='10' rx='4' fill='%23fff' opacity='.45'/%3E%3Cpath d='M13 7l10 5-10 5z' fill='%23133a58'/%3E%3C/g%3E%3Cg transform='translate(32,0)'%3E%3Crect x='1' y='1' width='30' height='22' rx='4' fill='url(%23b)' stroke='%23ffffff'/%3E%3Crect x='1' y='1' width='30' height='10' rx='4' fill='%23fff' opacity='.7'/%3E%3Cpath d='M13 7l10 5-10 5z' fill='%230c2b47'/%3E%3C/g%3E%3Cg transform='translate(64,0)'%3E%3Crect x='1' y='2' width='30' height='22' rx='4' fill='%23276a9f' stroke='%23133a58'/%3E%3Cpath d='M13 8l10 5-10 5z' fill='%23dff1ff'/%3E%3C/g%3E%3C/svg%3E");
}
.transport-btn {
  width: 32px; height: 24px; border: 0; cursor: pointer;
  background: var(--sprite-play) no-repeat 0 0;
}
.transport-btn:hover  { background-position: -32px 0; }
.transport-btn:active { background-position: -64px 0; }
```

### 6.2 A 9-slice chrome frame via `border-image` (SVG data-URI)

```css
.frame {
  border: 14px solid transparent;
  border-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='44' height='44'%3E%3ClinearGradient id='m' x1='0' y1='0' x2='0' y2='1'%3E%3Cstop offset='0' stop-color='%23ffffff'/%3E%3Cstop offset='.5' stop-color='%23bcd6ec'/%3E%3Cstop offset='.5' stop-color='%239db9d4'/%3E%3Cstop offset='1' stop-color='%236e8db0'/%3E%3C/linearGradient%3E%3Crect x='1' y='1' width='42' height='42' rx='10' fill='url(%23m)' stroke='%23ffffff'/%3E%3Crect x='4' y='4' width='36' height='36' rx='7' fill='%23dff1ff' opacity='.45'/%3E%3C/svg%3E")
    14 14 14 14 fill / 14px / 0 stretch;
}
```

### 6.3 The visualizer palette (Winamp `viscolor.txt` → JS)

```js
// 24-entry ramp: dark → bright → white → hot highlight, indexed by band
const VISCOLOR = [
  [10,30,48],[16,48,72],[20,64,96],[24,84,124],[28,108,150],
  [36,132,178],[44,158,200],[56,182,222],[80,204,236],[110,222,240],
  [150,236,244],[190,244,244],[224,250,246],[244,252,248],[255,255,255],
  [255,248,224],[255,238,180],[255,224,140],[255,204,110],[255,180,80],
  [255,150,60],[255,120,50],[255,90,48],[255,60,60],
];
// band i uses VISCOLOR[Math.min(23, Math.floor(i * 24 / N_BANDS))]
```

---

## 7. Sources

- [Winamp Skin — Just Solve the File Format Problem](http://fileformats.archiveteam.org/index.php?title=Winamp_Skin) — bitmap atlas + `region.txt`/`viscolor.txt` format.
- [The Base Skin — Winamp Developer Wiki](http://wiki.winamp.com/index.php?title=The_Base_Skin) — reference bitmap dimensions/layout.
- [Editing the Configuration Files — Winamp Wiki](http://wiki.shoutcast.com/index.php?title=Editing_the_Configuration_Files) — `region.txt` / `viscolor.txt` / `pledit.txt` syntax.
- [Winamp Skinning Tutorial 1.5.0](https://manualzz.com/doc/41249924/) — strip-by-strip walkthrough (`cbuttons`, `volume`, `balance` filmstrips).
- [Region.txt help — Winamp forums](https://forums.winamp.com/forum/winamp/winamp-technical-support/50197-region-txt-help) and [Transparency thread](https://forums.winamp.com/forum/skinning-and-design/classic-skins/64923-transparency).
- [WMP Skin Definition File — Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/wmp/skin-definition-file) and [Complete Code for Simple Skin](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/wmp/complete-code-for-simple-skin) — `<VIEW>`/`<BUTTONGROUP>`/`mappingImage`/`hoverImage`/`downImage`/JScript.
- [WMP BUTTONGROUP Element — Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/wmp/buttongroup-element).
- [border-image-slice — MDN](https://developer.mozilla.org/en-US/docs/Web/CSS/border-image-slice) and [border-image — MDN](https://developer.mozilla.org/en-US/docs/Web/CSS/border-image) — CSS 9-slice.
- [MSSTYLES — Visual Explainer](https://vectree.io/c/msstyles) — sizing margins (9-slice) in theme bitmaps.
- [Nine-slice modal — Coherent Labs](https://coherent-labs.com/blog/uitutorials/nine-slice-modal/) — applied 9-slice example.

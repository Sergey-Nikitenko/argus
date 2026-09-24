# Frutiger Aero — CSS/HTML Implementation Spec (Argus Dashboard)

> Developer-grade construction spec. Every value below is copy-pasteable.
> Target: `dashboard/index.html` (single file, inline CSS, no assets/network/CDN).
> Where an image would normally be needed (9-slice frames, bubbles), we use inline
> SVG `data:` URIs so the build stays asset-free.
>
> Sources: [Frutiger Aero Archive — "How to nail the Web 2.0 Gloss look"](https://frutigeraeroarchive.org/blog/posts/20_09_2025),
> [ColorMagic Frutiger Aero palette](https://colormagic.app/palette/67449f87ed1554d4dbb0b226),
> [Frutiger Aero — Wikipedia](https://en.wikipedia.org/wiki/Frutiger_Aero),
> [CSS-Tricks — backdrop-filter](https://css-tricks.com/using-css-backdrop-filter-for-ui-effects/).

---

## 0. The one rule that matters

Frutiger Aero is **bright, airy, optimistic glass** — aqua/sky/soft-green over
white, with a *white specular gloss on the top half* and a *light top-left /
dark bottom-right bevel*. It is **never dark neon**. Every dark surface is
replaced by translucent white glass over a light aurora sky.

Order of operations on any control:

1. **Aurora sky** behind everything (soft blue/green/white radial glows).
2. **Glass panel** = translucent white gradient + `backdrop-filter` blur.
3. **Gloss** = white top-half specular gradient + 1px bright top edge.
4. **Bevel** = light top-left / dark bottom-right inset shadows.
5. **Soft drop shadow** = wide, low-opacity, blue-tinted.

---

## 1. Exact color palette

### 1.1 Core hues (opaque, for solids and gradient stops)

| Token | Hex | Use |
|---|---|---|
| `--aero-aqua` | `#00b4d8` | primary aqua (buttons, focus, accents) |
| `--aero-aqua-bright` | `#33c6e8` | aqua highlight band |
| `--aero-cyan` | `#6dd6ec` | mid cyan (aurora, chips) |
| `--aero-sky` | `#87ceeb` | sky blue (frames, headers) |
| `--aero-sky-pale` | `#cfe8f7` | pale sky (panel tint) |
| `--aero-ice` | `#dbf0ff` | near-white ice (glass base) |
| `--aero-green` | `#8fd8a8` | soft green (OK / healthy states) |
| `--aero-green-deep` | `#2a9d90` | green text / pressed depth |
| `--aero-green-pale` | `#d9f2e3` | green panel tint |
| `--aero-white` | `#ffffff` | specular, text on dark |
| `--aero-azure` | `#f0ffff` | azure near-white (page wash) |

Accent-adjacent (use sparingly): amber `#f6d06f`, coral `#e76e50`, violet
`#7c6581` — all pastel, never saturated neon.

### 1.2 Translucent glass tones (alpha-critical — use RGBA, never 8-digit hex)

| Token | Value | Use |
|---|---|---|
| `--glass-white` | `rgba(255,255,255,0.55)` | frosted panel body |
| `--glass-white-strong` | `rgba(255,255,255,0.72)` | modal / active panel |
| `--glass-aqua` | `rgba(190,230,255,0.35)` | tinted glass (nav, headers) |
| `--glass-green` | `rgba(200,240,215,0.35)` | success glass |
| `--glass-specular` | `rgba(255,255,255,0.95)` | top gloss start |
| `--glass-specular-end` | `rgba(255,255,255,0.00)` | top gloss end |
| `--glass-border` | `rgba(255,255,255,0.75)` | 1px top edge |
| `--bevel-dark` | `rgba(90,135,165,0.45)` | bottom-right bevel |
| `--bevel-light` | `rgba(255,255,255,0.85)` | top-left bevel |

### 1.3 Root token block (paste verbatim)

```css
:root {
  --aero-aqua:        #00b4d8;
  --aero-aqua-bright: #33c6e8;
  --aero-cyan:        #6dd6ec;
  --aero-sky:         #87ceeb;
  --aero-sky-pale:    #cfe8f7;
  --aero-ice:         #dbf0ff;
  --aero-green:       #8fd8a8;
  --aero-green-deep:  #2a9d90;
  --aero-green-pale:  #d9f2e3;
  --aero-white:       #ffffff;
  --aero-azure:       #f0ffff;

  --glass-white:         rgba(255,255,255,0.55);
  --glass-white-strong:  rgba(255,255,255,0.72);
  --glass-aqua:          rgba(190,230,255,0.35);
  --glass-green:         rgba(200,240,215,0.35);
  --glass-specular:      rgba(255,255,255,0.95);
  --glass-specular-end:  rgba(255,255,255,0.00);
  --glass-border:        rgba(255,255,255,0.75);
  --bevel-dark:          rgba(90,135,165,0.45);
  --bevel-light:         rgba(255,255,255,0.85);

  --aero-font: "Segoe UI", "Segoe UI Semilight", Tahoma, "Arial", sans-serif;
}
```

---

## 2. The gloss technique (specular highlight) — *the* signature

A glossy Aero surface is **base color + a white gradient that fades to
transparent in the top ~45–50%** + a **1px bright top edge**. Two recipes:

### 2.1 Soft specular (smooth glass — for panels, glass regions)

```css
.aero-gloss {
  background:
    linear-gradient(to bottom,
      var(--glass-specular)     0%,   /* near-solid white at the very top  */
      rgba(255,255,255,0.55)    8%,   /* quick falloff                      */
      rgba(255,255,255,0.12)   40%,   /* glass band                         */
      rgba(255,255,255,0.00)   52%,   /* transparent by the vertical middle */
      rgba(255,255,255,0.00)  100%);
  box-shadow:
    inset 0 1px 0 var(--glass-border); /* THE 1px bright top edge */
}
```

### 2.2 Hard-stop gloss (gel buttons — the "straight line" glass band)

From the [Frutiger Aero Archive gloss tutorial](https://frutigeraeroarchive.org/blog/posts/20_09_2025):
the base gradient uses **two stops at the same percentage** (a hard stop) to
draw a crisp separation line between the glossy top and the darker body.

```css
/* Base gel body (aqua example) — note 55% twice = hard stop */
.aero-button-aqua {
  background: linear-gradient(to bottom,
    #bfefff 0%,
    #4ecdf2 55%,   /* hard stop: top/lit half ends here */
    #00a5d1 55%,   /* hard stop: bottom/shaded half starts here */
    #1f7ea8 100%);
}

/* The reflection overlay — ::before, half-height, white fading down */
.aero-button-aqua::before {
  content: "";
  position: absolute;
  top: 0; left: 5%; width: 90%;
  height: 50%;                 /* covers only the top half */
  border-radius: 9999px 9999px 0 0;
  background: linear-gradient(to bottom,
    rgb(255,255,255) 0%,
    rgba(255,255,255,0.4) 100%);
  opacity: 0.45;               /* tune 0.3–0.55 by lightness of base */
  pointer-events: none;
}
```

Canonical **green** gel body (verbatim from the archive):

```css
background: linear-gradient(to bottom,
  #c8ffc5 0%,
  #1fbf24 55%,
  #009a05 55%,
  #457a28 100%);
```

> Rule of thumb for any hue: `top-lit = mix(white, hue, ~70%)`, `bottom-shaded =
> hue darkened ~40%`. Keep the 55% hard stop fixed — it is the glass-band seam.

---

## 3. Beveling (raised vs recessed)

Light source is top-left (consistent everywhere). Bevel = inset box-shadows,
**not** borders (borders eat the gloss). Raised controls catch light top-left
and shade bottom-right; recessed controls invert it.

### 3.1 Raised (buttons, tabs, tiles)

```css
.aero-raised {
  box-shadow:
    inset 1px 1px 0    var(--bevel-light),   /* top-left light   */
    inset 2px 2px 2px  rgba(255,255,255,0.5),/* diffuse top glow */
    inset -1px -1px 0  var(--bevel-dark),    /* bottom-right dark*/
    inset -2px -2px 3px rgba(70,120,150,0.30);
  border: 1px solid rgba(120,165,195,0.45);
}
```

### 3.2 Recessed (wells, inputs, inset panes, pressed state)

```css
.aero-recessed {
  background: linear-gradient(to bottom,
    rgba(150,200,225,0.18),
    rgba(255,255,255,0.55));
  box-shadow:
    inset 1px 1px 3px  rgba(45,90,120,0.35),  /* top-left dark   */
    inset -1px -1px 0  rgba(255,255,255,0.85);/* bottom-right light */
  border: 1px solid rgba(120,165,195,0.35);
}
```

### 3.3 Pressed (toggle a raised button in place — swap classes only)

```css
.aero-raised:active,
.aero-raised.is-pressed {
  background: linear-gradient(to bottom, #bcd8e8 0%, #d9ecf5 100%); /* flip gradient */
  box-shadow: inset 1px 1px 3px rgba(45,90,120,0.4), inset -1px -1px 0 rgba(255,255,255,0.7);
}
```

---

## 4. 9-slice frame scaling (XP Luna "sizing margins" → CSS `border-image`)

Luna/Vista frames are bitmaps with **sizing margins**: corner regions are drawn
1:1, edges stretch, the center is the fill. In CSS this is `border-image` with
`border-image-slice`. For a single-file build, the source is an **inline SVG
`data:` URI** (no asset file, no network).

### 4.1 Inline SVG frame (beveled rounded aqua frame)

```css
/* URL-encode once; keep # as %23. 16px corners, 1px bevel edge. */
.aero-frame {
  border-style: solid;
  border-width: 16px;
  border-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='64' height='64' viewBox='0 0 64 64'%3E%3Crect x='1.5' y='1.5' width='61' height='61' rx='12' fill='rgba(255,255,255,0.55)'/%3E%3Crect x='1' y='1' width='62' height='62' rx='12' fill='none' stroke='rgba(255,255,255,0.85)' stroke-width='1.5'/%3E%3Crect x='0.5' y='0.5' width='63' height='63' rx='12' fill='none' stroke='rgba(90,135,165,0.5)' stroke-width='1'/%3E%3C/svg%3E") 16 / 16px / 0 stretch;
  border-image-slice: 16 fill;   /* `fill` paints the center region too */
  background: var(--glass-white);
}
```

Key numbers:
- `border-width: 16px` = the slice size = the Luna "sizing margin" per edge.
- `border-image-slice: 16` = cut the source into 9 cells at 16px from each edge.
- The 4 corners render 1:1; top/bottom/left/right edges stretch; `fill` uses the
  center cell as the background (otherwise `background` shows through).

### 4.2 No-image fallback: layered box-shadows (same bevel, fully CSS)

```css
.aero-frame-css {
  background:
    linear-gradient(to bottom, var(--glass-white), rgba(255,255,255,0.35));
  border: 1px solid rgba(120,165,195,0.4);
  border-radius: 12px;
  box-shadow:
    inset 0 1px 0 rgba(255,255,255,0.9),   /* top edge          */
    inset 1px 0 0 rgba(255,255,255,0.7),   /* left edge         */
    inset 0 -1px 0 rgba(90,135,165,0.35),  /* bottom edge       */
    inset -1px 0 0 rgba(90,135,165,0.30),  /* right edge        */
    inset 1px 1px 2px rgba(255,255,255,0.6),
    inset -1px -1px 3px rgba(70,120,150,0.25);
}
```

### 4.3 Sizing-margin truth table (for building your own SVG frames)

| Region | Behavior | CSS equivalent |
|---|---|---|
| 4 corners | drawn 1:1 (never stretched) | `border-image-slice` corner cells |
| 4 edges | stretched along their axis | slice edge cells, `stretch` repeat |
| center | stretched both axes (or `fill`) | slice center cell |

Rule: **corner radius of the frame == slice size** (`rx` ≈ slice px) so corners
scale without distortion — this is exactly why Luna bundled a fixed corner size
in the theme.

---

## 5. Frosted-glass blur + translucency + specular streaks

Aero glass = **translucent white** + **mild blur** (1–4px — not the 20px+ of
2020s "glassmorphism", which reads as frosted, not Aero) + **saturation bump** +
optional **diagonal specular streaks**.

### 5.1 The panel

```css
.aero-glass-panel {
  background: linear-gradient(135deg,
    rgba(255,255,255,0.62) 0%,
    rgba(210,240,255,0.40) 50%,
    rgba(255,255,255,0.55) 100%);
  backdrop-filter: blur(3px) saturate(150%);
  -webkit-backdrop-filter: blur(3px) saturate(150%);
  border: 1px solid rgba(255,255,255,0.7);
  border-radius: 12px;
}
```

> The archive's own guidance: **"1 to 2 pixels of blur"** for Aero glass; more
> reads frosted. `blur(3px)` + `saturate(150%)` is the sweet spot for a light
> background. Increase alpha (to `0.72`) instead of blur for low-contrast areas.

### 5.2 Specular streaks (the "glass panes catch light" diagonal sheen)

```css
.aero-glass-panel::after {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: inherit;
  background:
    linear-gradient(115deg,
      rgba(255,255,255,0.55) 0%,
      rgba(255,255,255,0.12) 18%,
      rgba(255,255,255,0.00) 30%),
    repeating-linear-gradient(115deg,
      rgba(255,255,255,0.16) 0px,
      rgba(255,255,255,0.00) 2px,
      rgba(255,255,255,0.00) 9px,
      rgba(255,255,255,0.06) 11px);
  opacity: 0.6;
  pointer-events: none;
}
```

### 5.3 Fallback (older engine, no `backdrop-filter`)

Stack a **static blurred backdrop** is impossible without assets; instead raise
alpha and drop the blur so panels stay legible:

```css
@supports not (backdrop-filter: blur(1px)) {
  .aero-glass-panel { background: rgba(214,240,252,0.85); }
}
```

---

## 6. Aurora gradient backgrounds (the sky glow)

The FA backdrop is a **soft multi-radial sky**: white sun-glow top, aqua/sky
mid, soft green horizon. Build as stacked radial + one linear base.

```css
.aero-aurora {
  background:
    radial-gradient(ellipse 80% 60% at 18% 12%,
      rgba(255,255,255,0.90) 0%,
      rgba(205,240,255,0.00) 55%),              /* sun / white glow    */
    radial-gradient(ellipse 70% 55% at 82% 18%,
      rgba(140,225,250,0.65) 0%,
      rgba(140,225,250,0.00) 60%),              /* aqua bloom          */
    radial-gradient(ellipse 75% 60% at 55% 92%,
      rgba(150,230,180,0.55) 0%,
      rgba(150,230,180,0.00) 58%),              /* green horizon       */
    linear-gradient(180deg,
      #a9ddf4 0%,
      #c8e9f8 34%,
      #e3f6ee 66%,
      #d3eefb 100%);                            /* base sky wash       */
  background-attachment: fixed;                 /* glows stay put on scroll */
}
```

Dimmer "dawn" variant (for a calmer workspace):

```css
.aero-aurora-soft {
  background:
    radial-gradient(ellipse 90% 70% at 30% 10%,
      rgba(255,255,255,0.85) 0%, rgba(190,230,250,0.0) 55%),
    radial-gradient(ellipse 80% 60% at 75% 20%,
      rgba(120,210,240,0.5) 0%, rgba(120,210,240,0.0) 55%),
    radial-gradient(ellipse 80% 60% at 50% 95%,
      rgba(150,220,170,0.45) 0%, rgba(150,220,170,0.0) 55%),
    linear-gradient(180deg, #b7e0f5 0%, #d6edf9 45%, #e6f6ec 100%);
}
```

---

## 7. Bubble / water / bokeh / light-ray motifs

All CSS or inline-SVG — no image assets.

### 7.1 Bubble orb (CSS radial gradients)

```css
.aero-bubble {
  width: 90px; height: 90px; border-radius: 50%;
  background:
    radial-gradient(circle at 32% 28%,
      rgba(255,255,255,0.95) 0%,
      rgba(255,255,255,0.25) 12%,
      rgba(255,255,255,0.00) 22%),            /* specular dot        */
    radial-gradient(circle at 50% 50%,
      rgba(200,240,255,0.15) 0%,
      rgba(140,215,245,0.35) 60%,
      rgba(90,180,215,0.30) 100%);            /* body                */
  box-shadow:
    inset 0 0 6px rgba(255,255,255,0.7),
    inset -4px -6px 10px rgba(70,150,190,0.25),
    0 2px 6px rgba(90,140,170,0.25);          /* soft drop           */
  border: 1px solid rgba(255,255,255,0.8);    /* rim                 */
}
```

### 7.2 Concentric water rings

```css
.aero-ring {
  border-radius: 50%;
  background: repeating-radial-gradient(circle,
    rgba(255,255,255,0.0) 0px,
    rgba(255,255,255,0.0) 7px,
    rgba(255,255,255,0.45) 8px,
    rgba(255,255,255,0.0) 10px);
}
/* animate the spread with a keyframe scaling opacity 0.8 -> 0 */
```

### 7.3 Bokeh field (scattered soft discs)

One `::before` layer of many radial dots; animate `transform`/`opacity` slowly:

```css
.aero-bokeh::before {
  content: "";
  position: absolute; inset: 0;
  background-image:
    radial-gradient(circle 14px at 12% 22%, rgba(255,255,255,0.5), transparent 70%),
    radial-gradient(circle 9px  at 34% 70%, rgba(200,240,255,0.45), transparent 70%),
    radial-gradient(circle 22px at 58% 30%, rgba(255,255,255,0.35), transparent 70%),
    radial-gradient(circle 12px at 78% 64%, rgba(190,240,230,0.45), transparent 70%),
    radial-gradient(circle 18px at 88% 12%, rgba(255,255,255,0.40), transparent 70%);
  pointer-events: none;
}
```

### 7.4 Light rays (rotated gradient wedges, soft-blurred)

```css
.aero-rays {
  position: absolute; inset: 0; overflow: hidden; pointer-events: none;
}
.aero-rays::before {
  content: "";
  position: absolute; top: -30%; left: -20%;
  width: 140%; height: 130%;
  background: conic-gradient(from -20deg at 20% -10%,
    rgba(255,255,255,0.0)  0deg,
    rgba(255,255,255,0.28) 8deg,
    rgba(255,255,255,0.0)  18deg,
    rgba(255,255,255,0.0)  55deg,
    rgba(255,255,255,0.22) 66deg,
    rgba(255,255,255,0.0)  78deg,
    rgba(255,255,255,0.0)  130deg,
    rgba(255,255,255,0.20) 142deg,
    rgba(255,255,255,0.0)  154deg);
  filter: blur(6px);
  opacity: 0.5;
}
```

### 7.5 Bubble as inline SVG (crisp, reusable, scales losslessly)

```css
.aero-bubble-svg {
  background: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cdefs%3E%3CradialGradient id='b' cx='0.35' cy='0.3' r='0.9'%3E%3Cstop offset='0' stop-color='%23ffffff' stop-opacity='0.9'/%3E%3Cstop offset='0.25' stop-color='%23d9f4ff' stop-opacity='0.35'/%3E%3Cstop offset='1' stop-color='%238fd2ef' stop-opacity='0.25'/%3E%3C/radialGradient%3E%3C/defs%3E%3Ccircle cx='50' cy='50' r='48' fill='url(%23b)' stroke='%23ffffff' stroke-opacity='0.8'/%3E%3Cellipse cx='36' cy='30' rx='14' ry='9' fill='%23ffffff' opacity='0.9' transform='rotate(-30 36 30)'/%3E%3C/svg%3E") no-repeat center / cover;
}
```

---

## 8. Rounded corners + soft drop shadows (the era's softness)

- **Corners:** 6–16px. Controls `6–8px`, tiles/cards `10–12px`, panels/windows
  `12–16px`. Never square, never pill-shaped (pills read "modern").
- **Drop shadows:** wide, low-opacity, **blue-tinted** (not black/gray), with a
  faint second highlight shadow beneath.

```css
.aero-shadow-soft {
  box-shadow:
    0 2px 6px  rgba(90,140,170,0.22),   /* close, soft  */
    0 8px 24px rgba(90,140,170,0.18);   /* far, ambient */
}

.aero-shadow-window {
  box-shadow:
    0 1px 0  rgba(255,255,255,0.85),    /* top rim light */
    0 12px 32px rgba(60,110,145,0.28),
    0 2px 8px  rgba(60,110,145,0.20);
}
```

---

## 9. Typography & finish notes

- **Font stack:** `"Segoe UI", "Segoe UI Semilight", Tahoma, Arial, sans-serif`.
  Use light weights (300) for large headings, 400 for body — the era is slim
  and clean, not bold. ([Archive recommendation](https://frutigeraeroarchive.org/blog/posts/20_09_2025).)
- **Text color:** dark slate-blue on light — `#24435c` primary, `#5b7a92`
  secondary. Never pure `#000`; keep text ~`3:1`+ on glass.
- **No flat accents:** every solid hue gets the §2 gloss + §3 bevel treatment.
- **Reflections under objects** (the "standing on glass" floor): use
  `-webkit-box-reflect: below 2px linear-gradient(transparent 60%, rgba(255,255,255,0.4));`
  for imagery/logos, or a mirrored faded copy for universal support.

---

## 10. Canonical composite (copy-paste reference widget)

```html
<style>
  .aero-window {
    position: relative;
    width: 320px;
    border-radius: 14px;
    padding: 14px 16px;
    background: linear-gradient(135deg,
      rgba(255,255,255,0.66) 0%,
      rgba(210,240,255,0.42) 55%,
      rgba(255,255,255,0.58) 100%);
    backdrop-filter: blur(3px) saturate(150%);
    -webkit-backdrop-filter: blur(3px) saturate(150%);
    border: 1px solid rgba(255,255,255,0.75);
    box-shadow:
      inset 0 1px 0 rgba(255,255,255,0.9),
      0 12px 32px rgba(60,110,145,0.28),
      0 2px 8px  rgba(60,110,145,0.20);
  }
  .aero-window::before { /* specular top-half gloss */
    content: ""; position: absolute; inset: 0;
    border-radius: inherit; pointer-events: none;
    background: linear-gradient(to bottom,
      rgba(255,255,255,0.95) 0%,
      rgba(255,255,255,0.5) 8%,
      rgba(255,255,255,0.1) 42%,
      rgba(255,255,255,0) 52%);
  }
  .aero-btn {
    position: relative;
    display: inline-block;
    padding: 7px 18px;
    border-radius: 8px;
    color: #07324a;
    font: 400 13px "Segoe UI", Tahoma, sans-serif;
    text-shadow: 0 1px 0 rgba(255,255,255,0.7);
    background: linear-gradient(to bottom, #bfefff 0%, #4ecdf2 55%, #00a5d1 55%, #1f7ea8 100%);
    border: 1px solid rgba(70,130,165,0.5);
    box-shadow:
      inset 0 1px 0 rgba(255,255,255,0.9),
      inset 1px 1px 0 rgba(255,255,255,0.5),
      inset -1px -1px 0 rgba(40,90,120,0.4),
      0 2px 5px rgba(90,140,170,0.3);
    cursor: pointer;
  }
  .aero-btn::before { /* half-height reflection */
    content: ""; position: absolute; top: 1px; left: 8%; width: 84%; height: 48%;
    border-radius: 8px 8px 0 0;
    background: linear-gradient(to bottom, #ffffff 0%, rgba(255,255,255,0.4) 100%);
    opacity: 0.45; pointer-events: none;
  }
  .aero-btn:active {
    background: linear-gradient(to bottom, #bcd8e8 0%, #d9ecf5 100%);
    box-shadow: inset 1px 1px 3px rgba(45,90,120,0.4), inset -1px -1px 0 rgba(255,255,255,0.7);
  }
</style>

<div class="aero-aurora" style="padding:40px;">
  <div class="aero-window">
    <h2 style="margin:0 0 6px; font-weight:300; color:#24435c;">Argus</h2>
    <p style="margin:0 0 14px; color:#5b7a92;">Threats contained.</p>
    <button class="aero-btn">Restore</button>
  </div>
</div>
```

---

## Appendix — quick decisions log

1. **Glass alpha:** panels `0.55` white, active/modal `0.72`; tinted headers use
   aqua/green at `0.35`. Raise alpha (not blur) to fix contrast.
2. **Blur:** `blur(3px) saturate(150%)` for panels; `1–2px` for small chips;
   never exceed `6px` or it reads as 2020s frosted glassmorphism.
3. **Hard stop** at **55%** is the gel-button seam; keep it constant across hues.
4. **Light source top-left**, everywhere — bevels, gloss, shadows all agree.
5. **9-slice slice size = corner radius** (`16px`) for distortion-free corners.
6. **Shadow tint blue** (`rgba(90,140,170,…)`), never neutral black.
7. **Inline SVG `data:` URIs** replace every image asset (frames, bubbles) so the
   single-file, no-network constraint holds.

"""Convert the generated icon image into a multi-resolution Windows .ico.

Usage: py tools/make_icon.py
Requires Pillow: py -m pip install pillow
"""
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    raise SystemExit("Pillow not installed — run: py -m pip install pillow")

ROOT = Path(__file__).resolve().parent.parent
SIZES = [16, 24, 32, 48, 64, 128, 256]


def find_source() -> Path | None:
    for name in ("icon.png", "icon.jpg", "icon.jpeg"):
        p = ROOT / "dashboard" / name
        if p.exists():
            return p
    return None


def main() -> None:
    src = find_source()
    if src is None:
        raise SystemExit("no icon.png/.jpg in dashboard/ — run the Gemini icon generator first")
    img = Image.open(src).convert("RGBA")
    w, h = img.size
    s = min(w, h)
    img = img.crop(((w - s) // 2, (h - s) // 2, (w + s) // 2, (h + s) // 2))
    ico = ROOT / "dashboard" / "icon.ico"
    img.save(ico, format="ICO", sizes=[(sz, sz) for sz in SIZES])
    print(f"wrote {ico} ({s}x{s} source: {src.name})")


if __name__ == "__main__":
    main()

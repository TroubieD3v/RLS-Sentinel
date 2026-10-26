#!/usr/bin/env python3
"""Assemble docs/assets/frames/*.png (recorded by frontend/e2e/demo.spec.ts) into docs/assets/demo.gif.

    cd frontend && DEMO=1 SENTINEL_BIN=... npx playwright test e2e/demo.spec.ts --project=desktop
    python scripts/make_gif.py

Frame names are NNN-HOLD.png, where HOLD is the display time in 0.1 s ticks. Needs Pillow.
The palette is built from all frames together, so status colours that appear late (fail, warning) survive.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from PIL import Image

ASSETS = Path(__file__).resolve().parent.parent / "docs" / "assets"
SIZE = (1080, 675)


def main() -> None:
    files = sorted((ASSETS / "frames").glob("*.png"))
    if not files:
        raise SystemExit("no frames: record them with frontend/e2e/demo.spec.ts first")
    frames = [Image.open(f).convert("RGB").resize(SIZE, Image.Resampling.LANCZOS) for f in files]
    durations = [int(f.stem.split("-")[1]) * 100 for f in files]

    thumb = (SIZE[0] // 3, SIZE[1] // 3)
    sheet = Image.new("RGB", (thumb[0], thumb[1] * len(frames)))
    for i, im in enumerate(frames):
        sheet.paste(im.resize(thumb, Image.Resampling.BILINEAR), (0, i * thumb[1]))
    palette = sheet.quantize(colors=160, method=Image.Quantize.MEDIANCUT)
    images = [im.quantize(palette=palette, dither=Image.Dither.NONE) for im in frames]

    target = ASSETS / "demo.gif"
    images[0].save(target, save_all=True, append_images=images[1:], duration=durations, loop=0, optimize=True)
    shutil.rmtree(ASSETS / "frames")
    print(f"{target} {target.stat().st_size / 1024:.0f} KiB, {len(images)} frames, {sum(durations) / 1000:.1f} s")


if __name__ == "__main__":
    main()

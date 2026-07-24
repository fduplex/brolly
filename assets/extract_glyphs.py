#!/usr/bin/env python3
"""Extract the Nerd Font glyph outlines used by the README illustration into assets/nerd-glyphs.json.

`brolly ps1` draws its pill with Nerd Font glyphs. The README illustration must look identical to a reader who
has no such font installed, so the glyphs ship as vector paths rather than text: this script pulls the real
outlines out of the font once, and gen_prompt_states.py bakes them into the .svg.

Run it only when the glyph set changes (fontTools is in the dev dependency group):

    curl -sLo /tmp/nf.zip https://github.com/ryanoasis/nerd-fonts/releases/latest/download/NerdFontsSymbolsOnly.zip
    unzip -o /tmp/nf.zip -d /tmp/nf
    uv run python assets/extract_glyphs.py /tmp/nf/SymbolsNerdFont-Regular.ttf

Upstream glyph sources, via Nerd Fonts: dev-aws from Devicons (MIT), fa-clock_o / fa-xmark from Font Awesome
Free (icons CC BY 4.0), pl-left_hard_divider from Powerline (MIT).
"""

import json
import sys
from pathlib import Path

from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont

# The same codepoints src/brolly/prompt.py writes to the terminal.
WANTED = {
    'aws': 0xE7AD,  # nf-dev-aws
    'clock': 0xF017,  # nf-fa-clock_o
    'cross': 0xF00D,  # nf-fa-times
}

_OUT = Path(__file__).parent / 'nerd-glyphs.json'


def main(font_path: str) -> int:
    font = TTFont(font_path)
    cmap, glyphs = font.getBestCmap(), font.getGlyphSet()

    out: dict[str, dict] = {}
    for name, codepoint in WANTED.items():
        glyph_name = cmap.get(codepoint)
        if glyph_name is None:
            print(f'{font_path}: no glyph for U+{codepoint:04X} ({name})', file=sys.stderr)
            return 1
        path_pen, bounds_pen = SVGPathPen(glyphs, ntos=lambda v: f'{v:.0f}'), BoundsPen(glyphs)
        glyphs[glyph_name].draw(path_pen)
        glyphs[glyph_name].draw(bounds_pen)
        out[name] = {
            'codepoint': f'U+{codepoint:04X}',
            'glyph': glyph_name,
            'bounds': [round(v, 1) for v in bounds_pen.bounds],
            'd': path_pen.getCommands(),
        }

    payload = {
        '_source': f'{Path(font_path).name} (Nerd Fonts symbols-only release)',
        '_license': 'dev-aws: Devicons, MIT. fa-*: Font Awesome Free, icons CC BY 4.0.',
        '_regenerate': 'uv run python assets/extract_glyphs.py <SymbolsNerdFont-Regular.ttf>',
        'units_per_em': font['head'].unitsPerEm,
        'glyphs': out,
    }
    _OUT.write_text(json.dumps(payload, indent=2) + '\n')
    print(f'wrote {_OUT} ({", ".join(out)})')
    return 0


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))

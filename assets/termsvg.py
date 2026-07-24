"""Shared drawing kit for the README's terminal illustrations.

Both generators here paint the same thing: a terminal window whose contents are laid out on a fixed monospace
grid, with brolly's Nerd Font glyphs inlined as real outlines (nerd-glyphs.json, see extract_glyphs.py) so a
reader needs no font. Text runs are pinned to the grid with `textLength`, so a viewer substituting a slightly
different monospace face still lands every column where it belongs.

Colours are xterm-256 -> hex, matching src/brolly/prompt.py and src/brolly/cli.py.
"""

import json
from pathlib import Path

_DATA = json.loads((Path(__file__).parent / 'nerd-glyphs.json').read_text())
_GLYPHS, _UPM = _DATA['glyphs'], _DATA['units_per_em']

# prompt.py's pill palette.
SHOULDER = '#444444'  # 238
LOGO = '#eeeeee'  # 255
ACCENT = '#d7875f'  # 173 (terracotta)
ALERT = '#d75f5f'  # 167 (muted red)

# cli.py's ANSI palette, as a 256-colour terminal renders it.
ORANGE = '#ffaf00'  # 38;5;214
GREEN = '#5faf5f'  # 32
RED = '#d75f5f'  # 31
FG = '#c8cfdd'  # default foreground
DIM = '#6e7891'  # 2 (dim)

# Terminal chrome.
BG = '#1b1e28'
TITLEBAR = '#141720'
PROMPT_FG = '#8f9bb3'  # the \u@\h:\w$ tail
CAPTION_FG = '#565f73'  # dim right-hand annotation
FONT = "ui-monospace,'DejaVu Sans Mono','Menlo','Consolas',monospace"

FS = 15  # font size
CW = 9.02  # monospace advance at FS (DejaVu Sans Mono ~0.601em)
TITLE_H = 40
MARGIN = 22  # left margin inside the terminal body

# Pill geometry.
ROWH = 34  # prompt row height
T = 15  # powerline triangle width (half the pill height)
PILLH = 24
PAD = 9  # inner text padding
WS = 34  # shoulder segment width

# Cap height each pill glyph is drawn at, tuned so the trio reads at one optical weight next to 15px text.
GLYPH_H = {'aws': 12.0, 'clock': 12.0, 'cross': 11.0}


def esc(s: str) -> str:
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def ink_height(name: str, em: float) -> float:
    """How tall this glyph draws when set at `em` pixels — its own ink, not the em box, so sizes stay comparable."""
    _, y0, _, y1 = _GLYPHS[name]['bounds']
    return em * (y1 - y0) / _UPM


def nf_glyph(name: str, cx: float, cy: float, color: str, height: float) -> str:
    """Place a Nerd Font outline centred on (cx, cy) at `height` px. Font space is y-up, so the transform flips it."""
    g = _GLYPHS[name]
    x0, y0, x1, y1 = g['bounds']
    scale = height / (y1 - y0)
    tx = cx - scale * (x0 + x1) / 2
    ty = cy + scale * (y0 + y1) / 2
    return (
        f'<g transform="translate({tx:.2f},{ty:.2f}) scale({scale:.5f},{-scale:.5f})" fill="{color}">'
        f'<path d="{g["d"]}"/></g>'
    )


def text(x: float, y: float, s: str, color: str, *, size: float = FS, bold: bool = False, grid: bool = True) -> str:
    """One run of monospace text on the grid. `grid` pins its width to len(s) cells so columns can't drift."""
    weight = ' font-weight="700"' if bold else ''
    length = f' textLength="{len(s) * CW:.2f}" lengthAdjust="spacing"' if grid else ''
    return (
        f'<text x="{x:.2f}" y="{y:.2f}" font-family="{FONT}" font-size="{size}"{weight} fill="{color}" '
        f'dominant-baseline="central" xml:space="preserve"{length}>{esc(s)}</text>'
    )


def pill(x: float, top: float, bg: str, fg: str, glyph: str | None, label: str) -> tuple[str, float]:
    """One prompt pill starting at x; returns (svg, x_after_the_closing_divider).

    The dividers are hand-drawn triangles — the same shape as U+E0B0, but sized to the pill so the seams close.
    """
    y = top + (ROWH - PILLH) / 2
    mid = y + PILLH / 2
    parts: list[str] = []

    # 1. shoulder segment + AWS mark
    parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{WS}" height="{PILLH}" fill="{SHOULDER}"/>')
    parts.append(nf_glyph('aws', x + WS / 2, mid, LOGO, GLYPH_H['aws']))
    sx = x + WS  # shoulder right edge

    # width of the state text region
    glyph_w = 20 if glyph else 0
    state_w = T + PAD + glyph_w + len(label) * CW + PAD

    # 2. state background (extends left under the divider so the shoulder triangle sits on it)
    parts.append(f'<rect x="{sx:.1f}" y="{y:.1f}" width="{state_w:.1f}" height="{PILLH}" fill="{bg}"/>')
    # 3. shoulder->state divider (shoulder-coloured triangle on state bg)
    parts.append(f'<path d="M{sx:.1f} {y:.1f} L{sx + T:.1f} {mid:.1f} L{sx:.1f} {y + PILLH:.1f} Z" fill="{SHOULDER}"/>')

    # 4. glyph + label
    tx = sx + T + PAD
    if glyph:
        parts.append(nf_glyph(glyph, tx + 6, mid, fg, GLYPH_H[glyph]))
        tx += glyph_w
    parts.append(text(tx, mid, label, fg, bold=True, grid=False))

    # 5. closing divider (state-coloured triangle on terminal bg)
    ex = sx + state_w
    parts.append(f'<path d="M{ex:.1f} {y:.1f} L{ex + T:.1f} {mid:.1f} L{ex:.1f} {y + PILLH:.1f} Z" fill="{bg}"/>')
    return ''.join(parts), ex + T


def window(width: int, height: int, title: str, body: str, aria: str) -> str:
    """The rounded window with its title bar and traffic lights, wrapped around already-positioned body svg."""
    dots = ''.join(
        f'<circle cx="{22 + i * 20}" cy="{TITLE_H / 2}" r="6" fill="{c}"/>'
        for i, c in enumerate(('#ff5f56', '#ffbd2e', '#27c93f'))
    )
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" \
viewBox="0 0 {width} {height}" role="img" aria-label="{esc(aria)}">
  <title>{esc(title)}</title>
  <rect width="{width}" height="{height}" rx="10" fill="{BG}"/>
  <path d="M0 10 a10 10 0 0 1 10 -10 h{width - 20} a10 10 0 0 1 10 10 v{TITLE_H - 10} h-{width} Z" fill="{TITLEBAR}"/>
  {dots}
  <text x="{width / 2}" y="{TITLE_H / 2}" font-family="{FONT}" font-size="12.5" fill="#565f73" \
text-anchor="middle" dominant-baseline="central">{esc(title)}</text>
  {body}
</svg>
'''

#!/usr/bin/env python3
"""Generate assets/prompt-states.svg — a self-contained illustration of the `brolly ps1` prompt pill.

The real pill is drawn with Nerd Font glyphs (powerline dividers, an AWS mark, clock/cross icons) and
xterm-256 colours. A README reader has none of that font, so this renders every separator and glyph as a
vector shape and hard-codes the 256-colour palette to true-colour hex. The output therefore looks identical
in any SVG viewer — GitHub included — with no font dependency.

Run `python assets/gen_prompt_states.py` after touching palette or copy; commit the regenerated .svg.
"""

# xterm-256 -> hex, matching src/brolly/prompt.py exactly.
SHOULDER = '#444444'  # 238
LOGO = '#eeeeee'  # 255
ACCENT = '#d7875f'  # 173 (terracotta)
ALERT = '#d75f5f'  # 167 (muted red)

# state -> (bg, fg, glyph)  where glyph is 'clock' | 'cross' | None
STATES = [
    ('live', ACCENT, '#303030', None, 'corp/corp-dev · Development Account', 'token still valid — nothing to do'),
    ('idle', '#585858', ACCENT, 'clock', 'corp/corp-dev · Development Account', 'lapsed — refreshes on next use'),
    ('gone', ALERT, '#ffffff', 'cross', 'corp/corp-dev · Development Account', 'no token — run brolly'),
    ('plain', SHOULDER, '#bcbcbc', None, 'legacy-keys', 'not an SSO profile'),
]

# Terminal chrome / layout.
BG = '#1b1e28'  # window background
TITLEBAR = '#141720'
PROMPT_FG = '#8f9bb3'  # the \u@\h:\w$ tail
CAPTION_FG = '#565f73'  # dim right-hand annotation
FONT = "ui-monospace,'DejaVu Sans Mono','Menlo','Consolas',monospace"

FS = 15  # font size
CW = 9.02  # monospace advance at FS (DejaVu Sans Mono ~0.601em)
ROWH = 34  # row height
T = 15  # powerline triangle width (half the pill height)
PILLH = 24  # pill height
PAD = 9  # inner text padding
WS = 34  # shoulder segment width

MARGIN = 22  # left margin inside terminal body
TITLE_H = 40
TOP = TITLE_H + 20
TAIL = 'alex@lab:~/src$'


def esc(s: str) -> str:
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def aws_mark(cx: float, cy: float) -> str:
    """The AWS 'smile' swoosh + arrowhead, near-white, centred on (cx, cy). ~18px wide."""
    return (
        f'<g transform="translate({cx - 9},{cy - 5})" fill="none" stroke="{LOGO}" '
        f'stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">'
        f'<path d="M0 2 Q9 9 17 3"/>'
        f'<path d="M13 1.4 L17.3 2.7 L15.4 6.6" fill="{LOGO}" stroke="none"/>'
        f'</g>'
    )


def clock(cx: float, cy: float, color: str) -> str:
    return (
        f'<g transform="translate({cx},{cy})" fill="none" stroke="{color}" '
        f'stroke-width="1.5" stroke-linecap="round">'
        f'<circle r="5.4"/><path d="M0 -3 V0 L2.6 1.8"/></g>'
    )


def cross(cx: float, cy: float, color: str) -> str:
    return (
        f'<g transform="translate({cx},{cy})" stroke="{color}" stroke-width="1.9" stroke-linecap="round">'
        f'<path d="M-4 -4 L4 4"/><path d="M4 -4 L-4 4"/></g>'
    )


def pill(x: float, top: float, name: str, bg: str, fg: str, glyph: str | None, label: str) -> tuple[str, float]:
    """Emit one pill starting at x; return (svg, x_after_the_closing_divider)."""
    ph = PILLH
    y = top + (ROWH - ph) / 2
    mid = y + ph / 2
    parts: list[str] = []

    # 1. shoulder segment + AWS mark
    parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{WS}" height="{ph}" fill="{SHOULDER}"/>')
    parts.append(aws_mark(x + WS / 2, mid))
    sx = x + WS  # shoulder right edge

    # width of the state text region
    glyph_w = 20 if glyph else 0
    text_w = len(label) * CW
    state_w = T + PAD + glyph_w + text_w + PAD

    # 2. state background (extends left under the divider so the shoulder triangle sits on it)
    parts.append(f'<rect x="{sx:.1f}" y="{y:.1f}" width="{state_w:.1f}" height="{ph}" fill="{bg}"/>')
    # 3. shoulder->state divider (shoulder-coloured triangle on state bg)
    parts.append(f'<path d="M{sx:.1f} {y:.1f} L{sx + T:.1f} {mid:.1f} L{sx:.1f} {y + ph:.1f} Z" fill="{SHOULDER}"/>')

    # 4. glyph + label
    tx = sx + T + PAD
    if glyph == 'clock':
        parts.append(clock(tx + 6, mid, fg))
        tx += glyph_w
    elif glyph == 'cross':
        parts.append(cross(tx + 6, mid, fg))
        tx += glyph_w
    parts.append(
        f'<text x="{tx:.1f}" y="{mid:.1f}" font-family="{FONT}" font-size="{FS}" font-weight="700" '
        f'fill="{fg}" dominant-baseline="central">{esc(label)}</text>'
    )

    # 5. closing divider (state-coloured triangle on terminal bg)
    ex = sx + state_w
    parts.append(f'<path d="M{ex:.1f} {y:.1f} L{ex + T:.1f} {mid:.1f} L{ex:.1f} {y + ph:.1f} Z" fill="{bg}"/>')
    return ''.join(parts), ex + T


def main() -> None:
    rows = []
    max_x = 0.0
    for i, (name, bg, fg, glyph, label, _caption) in enumerate(STATES):
        top = TOP + i * ROWH
        mid = top + ROWH / 2
        svg, after = pill(MARGIN, top, name, bg, fg, glyph, label)
        rows.append(svg)
        tail_x = after + CW  # one space
        rows.append(
            f'<text x="{tail_x:.1f}" y="{mid:.1f}" font-family="{FONT}" font-size="{FS}" '
            f'fill="{PROMPT_FG}" dominant-baseline="central">{esc(TAIL)}</text>'
        )
        max_x = max(max_x, tail_x + len(TAIL) * CW)

    # right-hand dim captions, column-aligned past the widest prompt
    cap_x = max_x + 30
    for i, (_name, *_rest, caption) in enumerate(STATES):
        top = TOP + i * ROWH
        mid = top + ROWH / 2
        rows.append(
            f'<text x="{cap_x:.1f}" y="{mid:.1f}" font-family="{FONT}" font-size="12.5" '
            f'fill="{CAPTION_FG}" dominant-baseline="central"># {esc(caption)}</text>'
        )

    width = int(cap_x + max(len('# ' + c) for *_r, c in STATES) * 7.6 + MARGIN)
    height = int(TOP + len(STATES) * ROWH + 22)

    dots = ''.join(
        f'<circle cx="{22 + i * 20}" cy="{TITLE_H / 2}" r="6" fill="{c}"/>'
        for i, c in enumerate(('#ff5f56', '#ffbd2e', '#27c93f'))
    )
    title = (
        f'<text x="{width / 2}" y="{TITLE_H / 2}" font-family="{FONT}" font-size="12.5" fill="#565f73" '
        f'text-anchor="middle" dominant-baseline="central">brolly ps1 — prompt pill states</text>'
    )

    body = '\n  '.join(rows)
    opening = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="brolly ps1 prompt pill states">'
    )
    svg = f'''{opening}
  <title>brolly ps1 prompt pill: live, idle, gone, plain</title>
  <rect width="{width}" height="{height}" rx="10" fill="{BG}"/>
  <path d="M0 10 a10 10 0 0 1 10 -10 h{width - 20} a10 10 0 0 1 10 10 v{TITLE_H - 10} h-{width} Z" fill="{TITLEBAR}"/>
  {dots}
  {title}
  {body}
</svg>
'''
    with open('assets/prompt-states.svg', 'w') as f:
        f.write(svg)
    print(f'wrote assets/prompt-states.svg ({width}x{height})')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Generate assets/prompt-states.svg — a self-contained illustration of the `brolly ps1` prompt pill.

Copy and layout live here; the drawing primitives (palette, glyph outlines, window chrome) live in termsvg.py.

Run `python assets/gen_prompt_states.py` after touching palette or copy; commit the regenerated .svg.
"""

from termsvg import (
    ACCENT,
    ALERT,
    CAPTION_FG,
    CW,
    MARGIN,
    PROMPT_FG,
    ROWH,
    SHOULDER,
    TITLE_H,
    pill,
    text,
    window,
)

# state -> (bg, fg, glyph)  where glyph is 'clock' | 'cross' | None
STATES = [
    ('live', ACCENT, '#303030', None, 'corp/corp-dev · Development Account', 'token still valid — nothing to do'),
    ('idle', '#585858', ACCENT, 'clock', 'corp/corp-dev · Development Account', 'lapsed — refreshes on next use'),
    ('gone', ALERT, '#ffffff', 'cross', 'corp/corp-dev · Development Account', 'no token — run brolly'),
    ('plain', SHOULDER, '#bcbcbc', None, 'legacy-keys', 'not an SSO profile'),
]

TOP = TITLE_H + 20
TAIL = 'alex@lab:~/src$'


def main() -> None:
    rows = []
    max_x = 0.0
    for i, (_name, bg, fg, glyph, label, _caption) in enumerate(STATES):
        top = TOP + i * ROWH
        mid = top + ROWH / 2
        svg, after = pill(MARGIN, top, bg, fg, glyph, label)
        rows.append(svg)
        tail_x = after + CW  # one space
        rows.append(text(tail_x, mid, TAIL, PROMPT_FG, grid=False))
        max_x = max(max_x, tail_x + len(TAIL) * CW)

    # right-hand dim captions, column-aligned past the widest prompt
    cap_x = max_x + 30
    for i, (_name, *_rest, caption) in enumerate(STATES):
        mid = TOP + i * ROWH + ROWH / 2
        rows.append(text(cap_x, mid, f'# {caption}', CAPTION_FG, size=12.5, grid=False))

    width = int(cap_x + max(len('# ' + c) for *_r, c in STATES) * 7.6 + MARGIN)
    height = int(TOP + len(STATES) * ROWH + 22)

    svg = window(
        width,
        height,
        'brolly ps1 — prompt pill states',
        '\n  '.join(rows),
        'brolly ps1 prompt pill states',
    )
    with open('assets/prompt-states.svg', 'w') as f:
        f.write(svg)
    print(f'wrote assets/prompt-states.svg ({width}x{height})')


if __name__ == '__main__':
    main()

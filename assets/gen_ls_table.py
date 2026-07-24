#!/usr/bin/env python3
"""Generate assets/ls-table.svg — an illustration of `brolly ls` over a made-up two-session config.

This does not redraw the table: it calls the real `cmd_ls` with a synthetic config and paints the ANSI it
writes. Column widths, headings, glyph choices, and colours therefore cannot drift from the shipped command —
if `ls` changes, re-running this picks the change up.

Two things are pinned so the committed .svg is reproducible: the clock (a frozen `now`, so the countdown and
the expiry stamp never move) and the timezone (UTC, so the stamp does not follow whoever regenerates it).

Run `python assets/gen_ls_table.py` after touching the `ls` table; commit the regenerated .svg.
"""

import io
import os
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

os.environ['TZ'] = 'UTC'
time.tzset()

from brolly import cli  # noqa: E402  — must follow the TZ pin above

from termsvg import (  # noqa: E402
    ACCENT,
    CW,
    DIM,
    FG,
    GREEN,
    MARGIN,
    ORANGE,
    PROMPT_FG,
    RED,
    ROWH,
    TITLE_H,
    ink_height,
    nf_glyph,
    pill,
    text,
    window,
)

NOW = datetime(2026, 7, 24, 17, 18, tzinfo=UTC)
CURRENT = 'corp-dev'  # what $AWS_PROFILE points at — `ls` paints this row's name orange

# One live session and one dead one, so the table shows both halves of the status column. `corp` matches the
# session used in the ps1 illustration; `acme` is invented.
SESSION_STATE = {'acme': ('gone', None), 'corp': ('live', datetime(2026, 7, 25, 0, 37, tzinfo=UTC))}

FULL_CONFIG = {
    'sso_sessions': {
        'acme': {'sso_region': 'us-west-2'},
        'corp': {'sso_region': 'us-east-1'},
    },
    'profiles': {
        'acme-sandbox': {
            'sso_session': 'acme',
            'sso_account_id': '444455556666',
            'sso_account_name': 'Acme Sandbox',
            'sso_role_name': 'SandboxAdmin',
        },
        'acme-billing': {
            'sso_session': 'acme',
            'sso_account_id': '210987654321',
            'sso_account_name': 'Acme Payer',
            'sso_role_name': 'BillingReadOnly',
        },
        # secure-mode profiles keep account/role under brolly_sso_* — that is what puts a green check in `secure`
        'corp-dev': {
            'sso_session': 'corp',
            'brolly_sso_account_id': '111122223333',
            'sso_account_name': 'Development Account',
            'brolly_sso_role_name': 'aws-admins',
        },
        'corp-prod': {
            'sso_session': 'corp',
            'brolly_sso_account_id': '999988887777',
            'sso_account_name': 'Production Account',
            'brolly_sso_role_name': 'aws-admins',
            'region': 'us-east-2',
        },
        'corp-shared': {
            'sso_session': 'corp',
            'brolly_sso_account_id': '555566667777',
            'sso_account_name': 'Shared Services',
            'brolly_sso_role_name': 'developers',
        },
    },
}

# ANSI SGR -> hex, and the Nerd Font codepoints `ls` writes -> nerd-glyphs.json names. The codepoints come
# straight off cli.py rather than being repeated here, so a glyph swap there cannot desync this illustration.
COLORS = {'0': FG, '2': DIM, '31': RED, '32': GREEN, '38;5;214': ORANGE}
GLYPHS = {
    cli._AWS: 'aws',
    cli._PULSE: 'pulse',
    cli._USER: 'user',
    cli._LOCK: 'lock',
    cli._ACCT: 'account',
    cli._ROLE: 'role',
    cli._GLOBE: 'globe',
    cli._CHECK: 'check',
    cli._CLOCK: 'clock',
    cli._CROSS: 'cross',
    cli._CURRENT: 'check_circle',
}
GLYPH_EM = 12.5  # every glyph set at one em, the way the terminal sets them — not tuned icon by icon

LINEH = 22  # table line height
TOP = TITLE_H + 16
PROMPT = 'alex@lab:~/src$'
COMMAND = ' brolly ls'


class _Tty(io.StringIO):
    """`cmd_ls` colours its output only when stdout is a tty; this is a tty as far as it can tell."""

    def isatty(self) -> bool:
        return True


def capture_ls() -> str:
    """Run the real `ls` against the synthetic config with the clock and the expiry files stubbed out."""

    class _Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW.astimezone(tz) if tz else NOW

    cli.datetime = _Frozen
    cli._expiry_path = lambda session, config, secure: Path(session)
    cli._state_for = lambda path: SESSION_STATE[path.name][0]
    cli._read_expiry = lambda path: SESSION_STATE[path.name][1]

    out = _Tty()
    stdout, sys.stdout = sys.stdout, out
    try:
        cli.cmd_ls(FULL_CONFIG, CURRENT, check=False)
    finally:
        sys.stdout = stdout
    return out.getvalue()


def draw_line(line: str, y: float) -> list[str]:
    """Paint one ANSI line onto the character grid: glyphs as outlines, everything else as pinned text runs."""
    parts: list[str] = []
    colour, col = FG, 0
    run, run_col = '', 0

    def flush() -> None:
        nonlocal run
        s, lead = run.strip(), len(run) - len(run.lstrip())
        run = ''
        if not s:
            return
        x = MARGIN + (run_col + lead) * CW
        if set(s) == {'─'}:  # the header rule: a rect, so no viewer can leave gaps between the dashes
            parts.append(f'<rect x="{x:.2f}" y="{y:.2f}" width="{len(s) * CW:.2f}" height="1" fill="{colour}"/>')
        else:
            parts.append(text(x, y, s, colour))

    for chunk in re.split(r'(\033\[[0-9;]*m)', line):
        if not chunk:
            continue
        if chunk.startswith('\033['):
            flush()
            colour = COLORS[chunk[2:-1]]
            run_col = col
            continue
        for ch in chunk:
            if ch in GLYPHS:
                flush()
                name = GLYPHS[ch]
                parts.append(nf_glyph(name, MARGIN + (col + 0.5) * CW, y, colour, ink_height(name, GLYPH_EM)))
                col += 1
                run_col = col
                continue
            if not run:
                run_col = col
            run += ch
            col += 1
        flush()
    flush()
    return parts


def main() -> None:
    lines = capture_ls().split('\n')
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()

    body: list[str] = []
    prompt_mid = TOP + ROWH / 2
    pill_svg, after = pill(MARGIN, TOP, ACCENT, '#303030', None, f'corp/{CURRENT} · Development Account')
    body.append(pill_svg)
    body.append(text(after + CW, prompt_mid, PROMPT, PROMPT_FG, grid=False))
    body.append(text(after + CW + len(PROMPT) * CW, prompt_mid, COMMAND, FG, grid=False))
    prompt_w = after + CW + (len(PROMPT) + len(COMMAND)) * CW

    table_top = TOP + ROWH + 10
    for i, line in enumerate(lines):
        body.extend(draw_line(line, table_top + i * LINEH + LINEH / 2))

    text_w = max(len(re.sub(r'\033\[[0-9;]*m', '', line).rstrip()) for line in lines) * CW
    width = int(max(prompt_w, MARGIN + text_w) + MARGIN)
    height = int(table_top + len(lines) * LINEH + 16)

    svg = window(
        width,
        height,
        'brolly ls — sessions, profiles, token status',
        '\n  '.join(body),
        'brolly ls output: two sso-sessions with their profiles, token status, accounts, roles and regions',
    )
    with open('assets/ls-table.svg', 'w') as f:
        f.write(svg)
    print(f'wrote assets/ls-table.svg ({width}x{height})')


if __name__ == '__main__':
    main()

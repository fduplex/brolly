#!/usr/bin/env python3
"""Generate assets/ls-table.svg — an illustration of `brolly ls` over a made-up two-session config.

This does not redraw the table: it calls the real `cmd_ls` with a synthetic config and paints the ANSI it
writes. Column widths, headings, glyph choices, and colours therefore cannot drift from the shipped command —
if `ls` changes, re-running this picks the change up.

Two things are pinned so the committed .svg is reproducible: the clock (a frozen `now`, so the countdown and
the expiry stamp never move) and the timezone (UTC, so the stamp does not follow whoever regenerates it).

Run `python assets/gen_ls_table.py` after touching the `ls` table; commit the regenerated .svg.
"""

import os
import time
from datetime import UTC, datetime
from pathlib import Path

os.environ['TZ'] = 'UTC'
time.tzset()

from brolly import cli  # noqa: E402  — must follow the TZ pin above

from ansi import paint, record  # noqa: E402
from climap import COLORS, GLYPHS, GLYPH_EM  # noqa: E402

from termsvg import (  # noqa: E402
    ACCENT,
    BG,
    CW,
    FG,
    MARGIN,
    PROMPT_FG,
    ROWH,
    TITLE_H,
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

LINEH = 22  # table line height
TOP = TITLE_H + 16
PROMPT = 'alex@lab:~/src$'
COMMAND = ' brolly ls'


def capture_ls() -> list[list]:
    """Run the real `ls` against the synthetic config with the clock and the expiry files stubbed out."""

    class _Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW.astimezone(tz) if tz else NOW

    cli.datetime = _Frozen
    cli._expiry_path = lambda session, config, secure: Path(session)
    cli._state_for = lambda path: SESSION_STATE[path.name][0]
    cli._read_expiry = lambda path: SESSION_STATE[path.name][1]

    return record(lambda: cli.cmd_ls(FULL_CONFIG, CURRENT, check=False)).trimmed()


def main() -> None:
    rows = capture_ls()

    body: list[str] = []
    prompt_mid = TOP + ROWH / 2
    pill_svg, after = pill(MARGIN, TOP, ACCENT, '#303030', None, f'corp/{CURRENT} · Development Account')
    body.append(pill_svg)
    body.append(text(after + CW, prompt_mid, PROMPT, PROMPT_FG, grid=False))
    body.append(text(after + CW + len(PROMPT) * CW, prompt_mid, COMMAND, FG, grid=False))
    prompt_w = after + CW + (len(PROMPT) + len(COMMAND)) * CW

    table_top = TOP + ROWH + 10
    body += paint(rows, x0=MARGIN, y0=table_top, lineh=LINEH, colours=COLORS, glyphs=GLYPHS, glyph_em=GLYPH_EM, bg=BG)

    width = int(max(prompt_w, MARGIN + max(len(r) for r in rows) * CW) + MARGIN)
    height = int(table_top + len(rows) * LINEH + 16)

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

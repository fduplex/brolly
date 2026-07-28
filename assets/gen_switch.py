#!/usr/bin/env python3
"""Generate assets/switch.svg — an illustration of a `brolly switch` session, picker and all.

Like gen_ls_table.py this drives the real command rather than redrawing it: `cmd_switch` runs against a stubbed
SSO client with a scripted keystroke stream, and the terminal it thinks it is writing to is a Screen (see
ansi.py) — so the arrow-key redraw, the reverse-video cursor row, and the final confirmation line are the
command's own output. Only the parts that would reach the network or ~/.aws are replaced.

Run `python assets/gen_switch.py` after touching the picker; commit the regenerated .svg.
"""

from types import SimpleNamespace

from brolly import cli

from ansi import paint, record

from climap import COLORS, GLYPHS, GLYPH_EM

from termsvg import ACCENT, BG, CW, FG, MARGIN, PROMPT_FG, ROWH, TITLE_H, pill, text, window

PROFILE = 'corp-prod'
SESSION = 'corp'
REGION = 'us-east-1'

# corp-prod is pointed at the wrong account — the reason to reach for `switch` in the first place.
WAS = ('111122223333', 'Development Account')
ROLE = 'aws-admins'

ACCOUNTS = [
    {'accountId': '111122223333', 'accountName': 'Development Account'},
    {'accountId': '999988887777', 'accountName': 'Production Account'},
    {'accountId': '555566667777', 'accountName': 'Shared Services'},
]
ROLES = ['aws-admins', 'developers', 'read-only']

# One step down off the current account, select it, then take the first role.
KEYS = iter(['down', 'enter', 'enter'])
PICKED = ACCOUNTS[1]

LINEH = 22
TOP = TITLE_H + 16
PROMPT = 'alex@lab:~/src$'
COMMAND = ' brolly switch'


def _sso_client(*_args, **_kwargs) -> SimpleNamespace:
    """Stand in for boto3's sso client: just the two paginators `_pick_account_role` walks."""
    pages = {
        'list_accounts': [{'accountList': ACCOUNTS}],
        'list_account_roles': [{'roleList': [{'roleName': r} for r in ROLES]}],
    }
    return SimpleNamespace(
        get_paginator=lambda name: SimpleNamespace(paginate=lambda **_kw: iter(pages[name])),
    )


def capture_switch() -> list[list]:
    """Run the real `switch` with the network, the keyboard, and the config writes stubbed out."""
    cli._profile_sso = lambda profile: (SESSION, REGION, WAS[0], ROLE)  # ty: ignore[invalid-assignment]
    cli._ensure_token = lambda profile, session: 'token'  # ty: ignore[invalid-assignment]
    # `aws configure set` — nothing to write for an illustration
    cli._aws = lambda *args, **kwargs: None  # ty: ignore[invalid-assignment]
    cli.boto3 = SimpleNamespace(client=_sso_client)  # ty: ignore[invalid-assignment]
    cli._read_key = lambda: next(KEYS)  # ty: ignore[invalid-assignment]
    # the picker puts the terminal in cbreak mode and restores it afterwards; neither applies to a fake tty
    cli.termios = SimpleNamespace(  # ty: ignore[invalid-assignment]
        tcgetattr=lambda fd: None, tcsetattr=lambda fd, when, attrs: None, TCSADRAIN=0
    )
    cli.tty = SimpleNamespace(setcbreak=lambda fd: None)  # ty: ignore[invalid-assignment]

    return record(lambda: cli.cmd_switch(PROFILE)).trimmed()


def prompt_row(top: float, account: str, command: str = '') -> tuple[list[str], float]:
    """A shell prompt line: the ps1 pill, the prompt tail, and optionally the command typed after it."""
    mid = top + ROWH / 2
    svg, after = pill(MARGIN, top, ACCENT, '#303030', None, f'{SESSION}/{PROFILE} · {account}')
    parts = [svg, text(after + CW, mid, PROMPT, PROMPT_FG, grid=False)]
    if command:
        parts.append(text(after + CW + len(PROMPT) * CW, mid, command, FG, grid=False))
    return parts, after + CW + (len(PROMPT) + len(command)) * CW


def main() -> None:
    rows = capture_switch()

    body, prompt_w = prompt_row(TOP, WAS[1], COMMAND)
    picker_top = TOP + ROWH + 10
    body += paint(rows, x0=MARGIN, y0=picker_top, lineh=LINEH, colours=COLORS, glyphs=GLYPHS, glyph_em=GLYPH_EM, bg=BG)

    # the payoff: the next prompt carries the account the switch just wrote
    after_top = picker_top + len(rows) * LINEH + 6
    tail, tail_w = prompt_row(after_top, PICKED['accountName'])
    body += tail

    width = int(max(prompt_w, tail_w, MARGIN + max(len(r) for r in rows) * CW) + MARGIN)
    height = int(after_top + ROWH + 12)

    svg = window(
        width,
        height,
        'brolly switch — repoint a profile',
        '\n  '.join(body),
        'brolly switch: an arrow-key picker choosing an account, then a role, then the confirmation line',
    )
    with open('assets/switch.svg', 'w') as f:
        f.write(svg)
    print(f'wrote assets/switch.svg ({width}x{height})')


if __name__ == '__main__':
    main()

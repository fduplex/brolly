#!/usr/bin/env python3
"""brolly — authenticate, repoint, or create AWS SSO profiles.

usage:
  brolly                             verify/refresh the current profile (same as `brolly refresh`)
  brolly login [-s <session>]        force a fresh device-code login for a session
  brolly switch                      pick a new account/role for $AWS_PROFILE (rewrites the profile in place)
  brolly refresh [<profile>] [-s <session>]
                                     cheaply verify/refresh a profile's credentials, logging in only if the
                                     session is dead; defaults to $AWS_PROFILE
  brolly add <profile> [-s <session>]
                                     create a new profile under an existing sso-session, pick its account/role,
                                     and leave it authenticated
  brolly ls [--no-check]             list every sso-session and its profiles, with token status; by default
                                     silently probes each session over the network to distinguish a dead SSO
                                     session from a merely-lapsed access token — --no-check skips that and reads
                                     local expiry files only

The expiry `ls` shows is the SSO *access token*'s (8h from a fresh login, an hour per silent renewal), never the
access-portal session's — that one lives only server-side, so each session line also notes whether it can renew
without a browser at all.

Bare `brolly` no longer force-logs-in — it refreshes the current profile; use `brolly login` for a forced login.

-s/--session asserts which sso-session you are operating under (default: the current $AWS_PROFILE's).
For refresh the target profile must actually belong to the asserted session, or the command fails loudly —
crossing sessions is always deliberate.

$AWS_PROFILE is never modified — it is the fixed handle; `switch` only changes what it resolves to, `add`
creates a new profile without changing which one the shell uses, and `refresh` targets the aws CLI with
--profile rather than touching the ambient env.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import termios
import tty
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NamedTuple

import boto3
import botocore.session
from botocore.exceptions import (
    BotoCoreError,
    SSOTokenLoadError,
    TokenRetrievalError,
    UnauthorizedSSOTokenError,
)
from botocore.tokens import create_token_resolver

from .prompt import State, _aws_config_path, _expiry_path, _state_for

type ProfileName = str
type SessionName = str
type Region = str
type AccountId = str
type RoleName = str
type AccessToken = str
type AwsConfig = dict[str, Any]  # botocore's full_config / scoped-config nested-dict shape
type Account = dict[str, str]  # a boto3 sso.list_accounts entry: accountId, accountName, emailAddress
type ProfileRow = tuple[ProfileName, list[str], bool]  # (profile, cells in _HEADERS order, is-secure)

_ORANGE = '\033[38;5;214m'
_DIM = '\033[2m'
_RESET = '\033[0m'

# nerd-font glyphs (match the shell prompt's AWS pill)
# Nerd Font glyphs as \u escapes (raw private-use bytes don't survive tooling); needs a Nerd Font to render.
_AWS = '\ue7ad'  # nf-dev-aws
_ACCT = '\uf19c'  # nf-fa-institution
_ROLE = '\uf084'  # nf-fa-key
_LOCK = '\uf023'  # nf-fa-lock
_GLOBE = '\uf0ac'  # nf-fa-globe
_CURSOR = '\uf0da'  # nf-fa-caret-right
_CURRENT = '\uf058'  # nf-fa-check-circle
_CHECK = '\uf00c'  # nf-fa-check
_CLOCK = '\uf017'  # nf-fa-clock_o
_CROSS = '\uf00d'  # nf-fa-times
_USER = '\uf007'  # nf-fa-user
_PULSE = '\uf21e'  # nf-fa-heartbeat

_GREEN = '\033[32m'
_RED = '\033[31m'

# `ls` status -> (colour, glyph); palette kept in step with the ps1 pill's live/idle/gone/plain states so the
# two surfaces read as one tool.
_STATUS_STYLES: dict[State, tuple[str, str]] = {
    'live': (_GREEN, _CHECK),
    'idle': (_ORANGE, _CLOCK),
    'gone': (_RED, _CROSS),
    'plain': (_DIM, '\u00b7'),
}

# `ls` profile-table columns: [profile, secure, account, role, region]. Every heading pairs the column's glyph with
# its word (the profile column with a user glyph); attribute rows repeat that glyph, and the secure cell is the one
# column carrying its own colour, so both the header and that cell are indexed off _SECURE_COL.
_PROFILE_COL = 0
_SECURE_COL = 1
_HEADERS = [f'{_USER} profile', f'{_LOCK} secure', f'{_ACCT} account', f'{_ROLE} role', f'{_GLOBE} region']

# The session line is column-aligned for its first two fields (`session` name, `status` indicator); the expiry
# detail then runs on as a colspan from the `profile` column rightward. The `session` heading carries the _AWS glyph
# over the session names, `status` a heartbeat glyph over the state indicators, and `profile` + the attribute
# headings sit over the nested profile columns. Session rows no longer lead with the _AWS glyph — the name itself
# now carries the orange, and the whole table hangs off a fixed left indent.
_SESSION_HEADING = f'{_AWS} session'
_STATUS_HEADING = f'{_PULSE} status'
_SESSION_INDENT = 3  # left margin the whole table (headings, rule, session and profile rows) starts from
# widest of `<glyph> <state word>` across every state, floored at the heading label — the status column never
# depends on the data, so it is sized once here
_STATUS_WIDTH = max(len(_STATUS_HEADING), *(len(f'{glyph} {state}') for state, (_, glyph) in _STATUS_STYLES.items()))


def _require_aws() -> None:
    """Fail early with install guidance if the AWS CLI v2 is not on PATH — brolly shells out to `aws`."""
    if shutil.which('aws') is None:
        raise SystemExit(
            'brolly needs the AWS CLI v2 (`aws`) on your PATH. Install it: '
            'https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html'
        )


def _aws(*args: str, capture: bool = True) -> subprocess.CompletedProcess[str]:
    """Run the aws CLI. capture=False lets an interactive command own the terminal (device-code login)."""
    result = subprocess.run(['aws', *args], text=True, capture_output=capture)
    if result.returncode != 0:
        detail = (result.stderr or '').strip() if capture else ''
        raise SystemExit(f'aws {" ".join(args)} failed{": " + detail if detail else ""}')
    return result


def _profile_sso(profile: ProfileName) -> tuple[SessionName, Region, AccountId | None, RoleName | None]:
    """Return (session, region, account_id, role) for the profile; exit if it is not an SSO profile."""
    session = botocore.session.Session(profile=profile)
    cfg = session.get_scoped_config()
    session_name: SessionName | None = cfg.get('sso_session')
    if not session_name:
        raise SystemExit(f"profile '{profile}' has no sso_session")
    region: Region = session.full_config['sso_sessions'][session_name]['sso_region']
    return session_name, region, cfg.get('sso_account_id'), cfg.get('sso_role_name')


def _resolve_token(profile: ProfileName) -> AccessToken | None:
    """A valid SSO access token — refreshed if the cached one lapsed; None if the SSO session itself is dead."""
    resolver = create_token_resolver(botocore.session.Session(profile=profile))
    try:
        token = resolver.load_token()
        return token.get_frozen_token().token if token is not None else None
    except TokenRetrievalError, SSOTokenLoadError, UnauthorizedSSOTokenError:
        return None


def _ensure_token(profile: ProfileName, session_name: SessionName) -> AccessToken:
    token = _resolve_token(profile)
    if token is not None:
        return token
    # the access-portal session itself has ended, so the refresh token is dead: log in interactively and re-resolve
    print(f"SSO session '{session_name}' expired — logging in…", file=sys.stderr)
    _aws('sso', 'login', '--sso-session', session_name, '--no-browser', '--use-device-code', capture=False)
    token = _resolve_token(profile)
    if token is None:
        raise SystemExit('could not obtain a valid SSO token after login')
    return token


def _read_key() -> str:
    ch = sys.stdin.read(1)
    if ch == '\x1b':
        return {'[A': 'up', '[B': 'down'}.get(sys.stdin.read(2), 'esc')
    if ch in ('\r', '\n'):
        return 'enter'
    if ch == '\x03':
        return 'ctrl-c'
    return ch


def _render(rows: list[str], idx: int, current: int) -> None:
    for i, row in enumerate(rows):
        cursor = f'{_ORANGE}{_CURSOR}{_RESET}' if i == idx else ' '
        dot = f'{_ORANGE}{_CURRENT}{_RESET}' if i == current else ' '
        body = f'\033[7m {row} {_RESET}' if i == idx else f' {row} '
        sys.stdout.write(f'\r\033[K  {cursor} {dot} {body}\n')


def _menu(header: str, columns: list[str], rows: list[list[str]], default: int, current: int) -> int:
    """Arrow-key selector over tabular rows; returns the chosen index. Falls back to numeric input off a TTY."""
    widths = [max(len(columns[c]), *(len(r[c]) for r in rows)) for c in range(len(columns))]
    lines = ['  '.join(cell.ljust(widths[c]) for c, cell in enumerate(row)) for row in rows]
    head = '  '.join(col.ljust(widths[c]) for c, col in enumerate(columns))

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print(f'\n{header}\n      {head}')
        for i, line in enumerate(lines):
            print(f'  {i + 1:>2}) {line}{"  ← current" if i == current else ""}')
        while True:
            try:
                raw = input(f'select [1-{len(rows)}] (default {default + 1})> ').strip()
            except EOFError:
                raise SystemExit(130) from None
            if not raw:
                return default
            if raw.isdigit() and 1 <= int(raw) <= len(rows):
                return int(raw) - 1

    idx = default
    print(f'\n{header}   {_DIM}↑/↓ move · enter select · q quit{_RESET}')
    print(f'      {_DIM}{head}{_RESET}')
    _render(lines, idx, current)
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    sys.stdout.write('\033[?25l')
    sys.stdout.flush()
    try:
        tty.setcbreak(fd)
        while True:
            key = _read_key()
            if key in ('up', 'k'):
                idx = (idx - 1) % len(rows)
            elif key in ('down', 'j'):
                idx = (idx + 1) % len(rows)
            elif key == 'enter':
                return idx
            elif key in ('q', 'esc', 'ctrl-c'):
                raise SystemExit(130)
            else:
                continue
            sys.stdout.write(f'\033[{len(rows)}A')
            _render(lines, idx, current)
            sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        sys.stdout.write('\033[?25h')
        sys.stdout.flush()


def cmd_login(session: SessionName) -> None:
    _aws('sso', 'login', '--sso-session', session, '--no-browser', '--use-device-code', capture=False)


def _pick_account_role(
    sso_region: Region, token: AccessToken, cur_account: AccountId | None = None, cur_role: RoleName | None = None
) -> tuple[Account, RoleName]:
    """Interactively choose an account and role for the session; pre-selects cur_account/cur_role when given."""
    sso = boto3.client('sso', region_name=sso_region)

    accounts: list[Account] = []
    for page in sso.get_paginator('list_accounts').paginate(accessToken=token):
        accounts.extend(page['accountList'])
    if not accounts:
        raise SystemExit('no accounts available for this session')
    accounts.sort(key=lambda a: a['accountName'])

    acct_current = next((i for i, a in enumerate(accounts) if a['accountId'] == cur_account), -1)
    rows = [[a['accountId'], a['accountName']] for a in accounts]
    header = f'{_AWS}  {_ACCT}  select account'
    account = accounts[_menu(header, ['ACCOUNT', 'NAME'], rows, max(acct_current, 0), acct_current)]
    account_id: AccountId = account['accountId']

    roles: list[RoleName] = []
    for page in sso.get_paginator('list_account_roles').paginate(accessToken=token, accountId=account_id):
        roles.extend(r['roleName'] for r in page['roleList'])
    if not roles:
        raise SystemExit(f'no roles available in {account_id}')
    if len(roles) == 1:
        role = roles[0]
        print(f'{_ROLE}  only role: {role}')
    else:
        role_current = next((i for i, r in enumerate(roles) if r == cur_role and account_id == cur_account), -1)
        header = f'{_AWS}  {_ROLE}  select role'
        role = roles[_menu(header, ['ROLE'], [[r] for r in roles], max(role_current, 0), role_current)]
    return account, role


def _write_account_role(profile: ProfileName, account: Account, role: RoleName) -> None:
    _aws('configure', 'set', 'sso_account_id', account['accountId'], '--profile', profile)
    _aws('configure', 'set', 'sso_role_name', role, '--profile', profile)
    _aws('configure', 'set', 'sso_account_name', account['accountName'], '--profile', profile)


def cmd_switch(profile: ProfileName) -> None:
    session_name, sso_region, cur_account, cur_role = _profile_sso(profile)
    token = _ensure_token(profile, session_name)
    account, role = _pick_account_role(sso_region, token, cur_account, cur_role)
    account_id = account['accountId']
    _write_account_role(profile, account, role)
    print(f'\n{_ORANGE}{_CHECK}{_RESET}  {profile} → {account_id} ({account["accountName"]}) / {role}')


def cmd_add(session: SessionName, new_profile: ProfileName, full_config: AwsConfig) -> None:
    sso_sessions = full_config['sso_sessions']
    profiles = full_config['profiles']

    if session not in sso_sessions:
        raise SystemExit(f"unknown sso-session '{session}' — available: {', '.join(sorted(sso_sessions))}")
    if new_profile in profiles:
        raise SystemExit(f"profile '{new_profile}' already exists — use `brolly switch` to repoint it")

    sso_region: Region = sso_sessions[session]['sso_region']
    sibling = next((p for p in profiles.values() if p.get('sso_session') == session), {})
    _aws('configure', 'set', 'sso_session', session, '--profile', new_profile)
    _aws('configure', 'set', 'region', sibling.get('region', sso_region), '--profile', new_profile)
    _aws('configure', 'set', 'output', sibling.get('output', 'json'), '--profile', new_profile)

    token = _ensure_token(new_profile, session)
    account, role = _pick_account_role(sso_region, token)
    account_id = account['accountId']
    _write_account_role(new_profile, account, role)
    print(f'\n{_ORANGE}{_CHECK}{_RESET}  added {new_profile} → {account_id} ({account["accountName"]}) / {role}')
    print(f'{_DIM}  use it: export AWS_PROFILE={new_profile}{_RESET}')


def _backfill_account_name(profile: ProfileName, sso_region: Region, account_id: AccountId | None) -> None:
    if not account_id:
        return
    if botocore.session.Session(profile=profile).get_scoped_config().get('sso_account_name'):
        return
    token = _resolve_token(profile)
    if token is None:
        return
    sso = boto3.client('sso', region_name=sso_region)
    for page in sso.get_paginator('list_accounts').paginate(accessToken=token):
        for a in page['accountList']:
            if a['accountId'] == account_id:
                _aws('configure', 'set', 'sso_account_name', a['accountName'], '--profile', profile)
                return


def _is_secure(profile_config: AwsConfig) -> bool:
    """True if the profile is in brolly secure mode — its account/role live under ``brolly_sso_*`` in the keychain."""
    return 'brolly_sso_account_id' in profile_config


def _secure_mode_tip(session_name: SessionName, full_config: AwsConfig) -> None:
    """A dim, one-line nudge toward secure mode after a credential-establishing action — unless already secured."""
    if any(_is_secure(c) for c in full_config['profiles'].values() if c.get('sso_session') == session_name):
        return
    print(
        f"{_DIM}tip: 'brolly secure enable -s {session_name}' keeps this session's token in your OS keychain, "
        f'not ~/.aws/sso/cache{_RESET}',
        file=sys.stderr,
    )


def cmd_refresh(
    target_profile: ProfileName, session: SessionName, full_config: AwsConfig, secure: bool = False
) -> None:
    profiles = full_config['profiles']
    if target_profile not in profiles:
        raise SystemExit(f"unknown profile '{target_profile}' — available: {', '.join(sorted(profiles))}")
    actual: SessionName | None = profiles[target_profile].get('sso_session')
    if not actual:
        raise SystemExit(f"profile '{target_profile}' is not an SSO profile (no sso_session)")
    if actual != session:
        raise SystemExit(
            f"profile '{target_profile}' is under session '{actual}', not '{session}' — use -s {actual} to target it"
        )
    if actual not in full_config['sso_sessions']:
        raise SystemExit(f"sso-session '{actual}' referenced by '{target_profile}' is not defined")
    sso_region: Region = full_config['sso_sessions'][actual]['sso_region']
    account_id: AccountId | None = profiles[target_profile].get('sso_account_id')
    check = subprocess.run(
        ['aws', 'sts', 'get-caller-identity', '--profile', target_profile, '--query', 'Arn', '--output', 'text'],
        text=True,
        capture_output=True,
    )
    if check.returncode != 0:
        print(f'{target_profile}: credentials unavailable — logging in…', file=sys.stderr)
        if secure:
            from brolly import keychain

            keychain.cmd_secure_login(actual, full_config)
        else:
            _aws('sso', 'login', '--sso-session', actual, '--no-browser', '--use-device-code', capture=False)
        arn = _aws(
            'sts', 'get-caller-identity', '--profile', target_profile, '--query', 'Arn', '--output', 'text'
        ).stdout.strip()
    else:
        arn = check.stdout.strip()
    _backfill_account_name(target_profile, sso_region, account_id)
    print(f'{_ORANGE}{_CHECK}{_RESET}  {target_profile} live → {arn}')


def _session_profiles(session_name: SessionName, full_config: AwsConfig) -> list[tuple[ProfileName, AwsConfig]]:
    return [(p, c) for p, c in full_config['profiles'].items() if c.get('sso_session') == session_name]


def _color(text: str, colour: str, tty: bool) -> str:
    return f'{colour}{text}{_RESET}' if tty else text


def _read_expiry(path: Path) -> datetime | None:
    try:
        expiry = datetime.fromisoformat(json.loads(path.read_text())['expiresAt'])
    except OSError, ValueError, KeyError:
        return None
    return expiry if expiry.tzinfo else expiry.replace(tzinfo=UTC)


def _read_refreshable(path: Path, secure: bool) -> bool | None:
    """Whether this session can get a new access token without a browser. None when the store can't say.

    The two stores answer differently: botocore's plaintext cache holds the refresh token itself, so its presence
    is the answer. A secure-mode sidecar is non-secret by design and instead records the flag brolly wrote beside
    the expiry — absent on sidecars written before that flag existed, hence the third state.
    """
    try:
        blob = json.loads(path.read_text())
    except OSError, ValueError:
        return None
    if not secure:
        return 'refreshToken' in blob
    refreshable = blob.get('refreshable')
    return refreshable if isinstance(refreshable, bool) else None


def _renewal_note(state: State, refreshable: bool | None) -> tuple[str, str] | None:
    """The (text, colour) trailing the expiry, saying whether this session renews itself or ends in a browser.

    Only meaningful while a token exists — 'gone' already reports the absence, and an unknown flag stays silent
    rather than guessing.
    """
    if state == 'gone' or refreshable is None:
        return None
    return ('auto-renews', _DIM) if refreshable else ('no refresh token — re-login at expiry', _ORANGE)


def _countdown(expiry: datetime) -> str:
    total = int((expiry - datetime.now(UTC)).total_seconds())
    sign, total = ('-', -total) if total < 0 else ('', total)
    hours, minutes = total // 3600, (total % 3600) // 60
    return f'{sign}{hours}h{minutes:02d}m' if hours else f'{sign}{minutes}m'


def _status_detail(state: State, expiry: datetime | None) -> str:
    """The expiry colspan only — the state word itself now lives in the `status` column, so it is not repeated here."""
    if state == 'gone':
        return 'no valid token'
    if expiry is None:
        return ''
    verb = 'expires' if expiry > datetime.now(UTC) else 'expired'
    return f'{verb} {expiry.astimezone():%Y-%m-%d %H:%M} ({_countdown(expiry)})'


def _probe_session(
    session_name: SessionName, profile: ProfileName, secure: bool, keychain_mod: Any, keyring_module: Any
) -> tuple[State, datetime | None] | None:
    """Silently probe a session's real liveness by asking botocore's SSO token machinery to refresh it.

    The provider only ever uses the ``refresh_token`` grant against sso-oidc — it never runs device authorization —
    so this can resolve the dead-session-vs-lapsed-token ambiguity without any risk of triggering interactive login.
    Returns ``(state, expiry)`` when the endpoint answered, or ``None`` when it was unreachable (offline) so the
    caller falls back to the local read.
    """
    try:
        if secure:
            if keyring_module is None:
                return None
            token = keychain_mod.load_secure_token(profile, session_name, keyring_module)
            if token is None:
                return 'gone', None
            return 'live', _read_expiry(keychain_mod._sidecar_path(keychain_mod._cache_key(session_name)))
        loaded = create_token_resolver(botocore.session.Session(profile=profile)).load_token()
        if loaded is None:
            return 'gone', None
        return 'live', loaded.get_frozen_token().expiration
    except SSOTokenLoadError, TokenRetrievalError, UnauthorizedSSOTokenError:
        return 'gone', None
    except BotoCoreError, OSError, SystemExit:
        # offline, keychain unavailable, or any other probe failure — never crash ls; fall back to the local read
        return None


class _Block(NamedTuple):
    """One session's resolved `ls` state — everything the table needs about it, sized and printed in one pass."""

    session: SessionName
    state: State
    expiry: datetime | None
    refreshable: bool | None
    rows: list[ProfileRow]


def _profile_cells(profile: ProfileName, cfg: AwsConfig, sso_region: Region) -> ProfileRow:
    """Raw (uncoloured) table cells for one profile row, plus whether it is secure — column order is _HEADERS."""
    account_id = cfg.get('sso_account_id') or cfg.get('brolly_sso_account_id') or '?'
    role = cfg.get('sso_role_name') or cfg.get('brolly_sso_role_name') or '?'
    name = cfg.get('sso_account_name')
    account = f'{account_id} ({name})' if name else account_id
    region = cfg.get('region') or sso_region or '?'
    secure = _is_secure(cfg)
    return profile, [profile, _CHECK if secure else _CROSS, account, role, region], secure


def _print_profiles(
    rows: list[ProfileRow],
    current: ProfileName | None,
    widths: list[int],
    profile_col: int,
    tty: bool,
) -> None:
    if not rows:
        print(f'{" " * profile_col}{_color("(no profiles)", _DIM, tty)}')
        return
    for profile, cells, secure in rows:
        parts: list[str] = []
        for c, cell in enumerate(cells):
            if c == _SECURE_COL:
                # centre the lone glyph, padding on the raw width — ANSI codes must not count toward the column
                colour = _GREEN if secure else _RED
                pad = widths[c] - len(cell)
                left = pad // 2
                parts.append(' ' * left + _color(cell, colour, tty) + ' ' * (pad - left))
            elif c == _PROFILE_COL and profile == current:
                # the current profile's name carries the orange; pad on the raw name so ANSI never skews the column
                parts.append(_color(cell, _ORANGE, tty) + ' ' * (widths[c] - len(cell)))
            else:
                parts.append(cell.ljust(widths[c]))
        # names all start at profile_col; no per-row marker cell — the current row is flagged by its orange name
        print(f'{" " * profile_col}{"  ".join(parts)}')


def _print_ls_footer(
    current: ProfileName | None,
    blocks: list[_Block],
    full_config: AwsConfig,
    tty: bool,
) -> None:
    """One line naming what $AWS_PROFILE resolves to, reusing the rows already resolved for the table above."""
    indent = ' ' * _SESSION_INDENT
    if current is None:
        hint = '(export AWS_PROFILE=<profile> to pick one)'
        print(f'{indent}{_color("AWS_PROFILE not set", _DIM, tty)}  {_color(hint, _DIM, tty)}')
        return
    found = next(((b.state, cells) for b in blocks for prof, cells, _ in b.rows if prof == current), None)
    if found is None:
        # set to a profile the table doesn't list: either absent from config, or present but non-SSO (ls lists
        # sso-sessions only) — no session state to show either way, so warn rather than fabricate a status
        note = (
            '(not an SSO profile — brolly ls lists sso-sessions only)'
            if current in full_config['profiles']
            else '(no such profile in ~/.aws/config)'
        )
        print(f'{indent}{_color(f"AWS_PROFILE → {current}", _RED, tty)}  {_color(note, _DIM, tty)}')
        return
    state, cells = found
    colour, glyph = _STATUS_STYLES[state]
    status = _color(f'{glyph} {state}', colour, tty)
    detail = f'{cells[2]} / {cells[3]}  {cells[4]}'  # account (id + name) / role  region — already resolved above
    lead = _color(_CURRENT, _ORANGE, tty)
    print(f'{indent}{lead}  AWS_PROFILE → {_color(current, _ORANGE, tty)}  {status}  {detail}')


def cmd_ls(full_config: AwsConfig, current: ProfileName | None, check: bool) -> None:
    sso_sessions = full_config['sso_sessions']
    if not sso_sessions:
        raise SystemExit('no sso-sessions configured — create one with `aws configure sso`')
    tty = sys.stdout.isatty()
    config = _aws_config_path()

    keychain_mod = keyring_module = None
    if check and any(_is_secure(c) for c in full_config['profiles'].values()):
        try:
            from brolly import keychain

            keychain_mod, keyring_module = keychain, keychain._configured_keyring()
        except Exception, SystemExit:
            keychain_mod = keyring_module = None

    # First pass: resolve every session's status and its profile rows so the profile columns can be sized once
    # across all sessions — the table stays aligned across session breaks instead of per-session.
    blocks: list[_Block] = []
    for session_name in sorted(sso_sessions):
        members = _session_profiles(session_name, full_config)
        secure = any(_is_secure(c) for _, c in members)
        sso_region: Region = sso_sessions[session_name].get('sso_region', '')
        path = _expiry_path(session_name, config, secure)
        state, expiry = _state_for(path), _read_expiry(path)
        if check and state == 'idle' and members:
            probed = _probe_session(session_name, members[0][0], secure, keychain_mod, keyring_module)
            if probed is not None:
                state, expiry = probed
        # read after any probe: a successful refresh rewrites the store, so this sees the post-refresh truth
        refreshable = _read_refreshable(path, secure)
        rows = [_profile_cells(p, c, sso_region) for p, c in sorted(members)]
        blocks.append(_Block(session_name, state, expiry, refreshable, rows))

    all_rows = [cells for b in blocks for _, cells, _ in b.rows]
    # each column is sized to the wider of its widest data cell and its heading label (glyph+word can be widest)
    data_widths = (max((len(cells[c]) for cells in all_rows), default=0) for c in range(len(_HEADERS)))
    widths = [max(w, len(_HEADERS[c])) for c, w in enumerate(data_widths)]
    session_width = max(len(_SESSION_HEADING), *(len(b.session) for b in blocks))
    # the profile column sits right of the two session-line fields (session name, status), each with a 2-space gap
    profile_col = _SESSION_INDENT + session_width + 2 + _STATUS_WIDTH + 2

    print()  # leading blank line — separates the table from the shell prompt
    heads: list[str] = [_SESSION_HEADING.center(session_width), _STATUS_HEADING.center(_STATUS_WIDTH)]
    heads += [label.center(widths[c]) for c, label in enumerate(_HEADERS)]
    head_line = '  '.join(heads)
    print(_color(f'{" " * _SESSION_INDENT}{head_line}', _DIM, tty))  # every heading centred over its column
    # a dim rule spans the table, from the left indent to the region column's right edge (the header line's width)
    print(_color(f'{" " * _SESSION_INDENT}{"─" * len(head_line)}', _DIM, tty))
    for block in blocks:
        colour, glyph = _STATUS_STYLES[block.state]
        status_raw = f'{glyph} {block.state}'
        # name/status cells padded on raw length (ANSI excluded); the expiry detail is a colspan from profile_col
        name_cell = _color(block.session, _ORANGE, tty) + ' ' * (session_width - len(block.session))
        status_cell = _color(status_raw, colour, tty) + ' ' * (_STATUS_WIDTH - len(status_raw))
        detail = _status_detail(block.state, block.expiry)
        line = f'{" " * _SESSION_INDENT}{name_cell}  {status_cell}'
        if detail:
            line += f'  {_color(detail, colour, tty)}'
        # the renewal note carries its own colour — a warning has to read as one even on a green 'live' row
        note = _renewal_note(block.state, block.refreshable)
        if note and detail:
            text, note_colour = note
            line += _color(f' · {text}', note_colour, tty)
        print(line)
        _print_profiles(block.rows, current, widths, profile_col, tty)
        print()  # blank row after each session group, including the last
    _print_ls_footer(current, blocks, full_config, tty)
    print()  # one final blank line so the footer breathes before the shell prompt returns


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='brolly', description='authenticate, repoint, or create AWS SSO profiles')
    # metavar lists only the public commands; `credential-process` and `ps1` are machine-facing, so they are
    # registered without help= (which keeps argparse from listing them) and left out of the metavar.
    sub = parser.add_subparsers(dest='cmd', metavar='{login,switch,refresh,add,ls,secure}')

    login = sub.add_parser('login', help='force a fresh device-code login for a session')
    login.add_argument('-s', '--session', help="sso-session to log into (default: current profile's)")

    sub.add_parser('switch', help='pick a new account/role for $AWS_PROFILE')

    refresh = sub.add_parser('refresh', help="verify/refresh a profile's credentials")
    refresh.add_argument('profile', nargs='?', help='target profile (default: $AWS_PROFILE)')
    refresh.add_argument('-s', '--session', help="assert the sso-session (default: current profile's)")

    add = sub.add_parser('add', help='create a new profile under an sso-session')
    add.add_argument('profile', help='new profile name')
    add.add_argument('-s', '--session', help="session to create it under (default: current profile's)")

    ls = sub.add_parser('ls', help='list sso-sessions and their profiles with token status')
    ls.add_argument(
        '--check',
        dest='check',
        action='store_true',
        default=True,
        help='silently probe each session for real liveness over the network (default)',
    )
    ls.add_argument(
        '--no-check', dest='check', action='store_false', help='skip the network probe; classify from local cache only'
    )

    secure = sub.add_parser('secure', help='opt-in OS-keychain token storage (credential_process mode)')
    secure_sub = secure.add_subparsers(dest='secure_cmd', required=True)
    for name, summary in (
        ('enable', 'move a session into the OS keychain and rewrite its profiles as credential_process'),
        ('disable', 'revert a session to the stock plaintext cache and purge its keychain token'),
        ('login', 're-authorize a secured session, refreshing its keychain token'),
    ):
        sp = secure_sub.add_parser(name, help=summary)
        sp.add_argument('-s', '--session', help="sso-session to operate on (default: current profile's)")
        if name == 'enable':
            sp.add_argument(
                '--backend',
                help='keyring backend dotted path to use and save (e.g. keyring_pass.PasswordStoreBackend); '
                'default: auto-detect an OS keychain, or pass if its store is set up',
            )

    cred = sub.add_parser('credential-process')
    cred.add_argument('--profile', required=True, help='the secured profile to vend credentials for')

    return parser


def _session_in_context(current: ProfileName, full_config: AwsConfig, override: SessionName | None) -> SessionName:
    """The sso-session to operate under: an explicit -s override, else the current profile's; exit if neither."""
    session = override or full_config['profiles'].get(current, {}).get('sso_session')
    if not session:
        raise SystemExit(
            f"no sso-session in context — current profile '{current}' has no sso_session; pass -s <session>"
        )
    return session


def main(argv: list[str]) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv or ['refresh'])

    if args.cmd == 'credential-process':
        # Machine-facing, invoked by the AWS SDK on every cold credential resolution: keep it lean — no aws CLI
        # requirement, no full_config scan — and let it own stdout for the credential JSON.
        from brolly import keychain

        keychain.cmd_credential_process(args.profile)
        return

    _require_aws()
    current: ProfileName = os.environ.get('AWS_PROFILE', 'default')
    full_config: AwsConfig = botocore.session.Session().full_config
    if args.cmd == 'login':
        session = _session_in_context(current, full_config, args.session)
        if session not in full_config['sso_sessions']:
            raise SystemExit(
                f"unknown sso-session '{session}' — available: {', '.join(sorted(full_config['sso_sessions']))}"
            )
        cmd_login(session)
        _secure_mode_tip(session, full_config)
    elif args.cmd == 'switch':
        if _is_secure(full_config['profiles'].get(current, {})):
            from brolly import keychain

            keychain.cmd_secure_switch(current, full_config)
        else:
            cmd_switch(current)
    elif args.cmd == 'refresh':
        target = args.profile or current
        secure = _is_secure(full_config['profiles'].get(target, {}))
        cmd_refresh(target, _session_in_context(current, full_config, args.session), full_config, secure)
    elif args.cmd == 'add':
        session = _session_in_context(current, full_config, args.session)
        cmd_add(session, args.profile, full_config)
        _secure_mode_tip(session, full_config)
    elif args.cmd == 'ls':
        # ls distinguishes "unset" from "set to 'default'" for its footer, so pass the raw env (None when unset)
        cmd_ls(full_config, os.environ.get('AWS_PROFILE'), args.check)
    elif args.cmd == 'secure':
        from brolly import keychain

        session = _session_in_context(current, full_config, args.session)
        if session not in full_config['sso_sessions']:
            raise SystemExit(
                f"unknown sso-session '{session}' — available: {', '.join(sorted(full_config['sso_sessions']))}"
            )
        if args.secure_cmd == 'enable':
            keychain.cmd_secure_enable(session, full_config, args.backend)
        elif args.secure_cmd == 'disable':
            keychain.cmd_secure_disable(session, full_config)
        else:
            keychain.cmd_secure_login(session, full_config)
    else:
        parser.print_usage(sys.stderr)
        raise SystemExit(2)


def app() -> None:
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        raise SystemExit(130) from None


if __name__ == '__main__':
    app()

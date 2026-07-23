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

Bare `brolly` no longer force-logs-in — it refreshes the current profile; use `brolly login` for a forced login.

-s/--session asserts which sso-session you are operating under (default: the current $AWS_PROFILE's).
For refresh the target profile must actually belong to the asserted session, or the command fails loudly —
crossing sessions is always deliberate.

$AWS_PROFILE is never modified — it is the fixed handle; `switch` only changes what it resolves to, `add`
creates a new profile without changing which one the shell uses, and `refresh` targets the aws CLI with
--profile rather than touching the ambient env.
"""

import argparse
import os
import shutil
import subprocess
import sys
import termios
import tty
from typing import Any

import boto3
import botocore.session
from botocore.exceptions import SSOTokenLoadError, TokenRetrievalError, UnauthorizedSSOTokenError
from botocore.tokens import create_token_resolver

type ProfileName = str
type SessionName = str
type Region = str
type AccountId = str
type RoleName = str
type AccessToken = str
type AwsConfig = dict[str, Any]  # botocore's full_config / scoped-config nested-dict shape
type Account = dict[str, str]  # a boto3 sso.list_accounts entry: accountId, accountName, emailAddress

_ORANGE = '\033[38;5;214m'
_DIM = '\033[2m'
_RESET = '\033[0m'

# nerd-font glyphs (match the shell prompt's AWS pill)
_AWS = ''  # amazon
_ACCT = ''  # institution / account
_ROLE = ''  # key / role
_CURSOR = ''  # caret-right
_CURRENT = ''  # check-circle
_CHECK = ''  # check


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
    """A valid SSO access token — refreshed if the hourly one lapsed; None if the 7-day session is dead."""
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
    # session fully expired (>7d): the refresh token is dead, so log in interactively, then resolve again
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


def cmd_refresh(target_profile: ProfileName, session: SessionName, full_config: AwsConfig) -> None:
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
        _aws('sso', 'login', '--sso-session', actual, '--no-browser', '--use-device-code', capture=False)
        arn = _aws(
            'sts', 'get-caller-identity', '--profile', target_profile, '--query', 'Arn', '--output', 'text'
        ).stdout.strip()
    else:
        arn = check.stdout.strip()
    _backfill_account_name(target_profile, sso_region, account_id)
    print(f'{_ORANGE}{_CHECK}{_RESET}  {target_profile} live → {arn}')


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='brolly', description='authenticate, repoint, or create AWS SSO profiles')
    sub = parser.add_subparsers(dest='cmd')

    login = sub.add_parser('login', help='force a fresh device-code login for a session')
    login.add_argument('-s', '--session', help="sso-session to log into (default: current profile's)")

    sub.add_parser('switch', help='pick a new account/role for $AWS_PROFILE')

    refresh = sub.add_parser('refresh', help="verify/refresh a profile's credentials")
    refresh.add_argument('profile', nargs='?', help='target profile (default: $AWS_PROFILE)')
    refresh.add_argument('-s', '--session', help="assert the sso-session (default: current profile's)")

    add = sub.add_parser('add', help='create a new profile under an sso-session')
    add.add_argument('profile', help='new profile name')
    add.add_argument('-s', '--session', help="session to create it under (default: current profile's)")

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
    _require_aws()
    current: ProfileName = os.environ.get('AWS_PROFILE', 'default')
    parser = _build_parser()
    args = parser.parse_args(argv or ['refresh'])
    full_config: AwsConfig = botocore.session.Session().full_config
    if args.cmd == 'login':
        session = _session_in_context(current, full_config, args.session)
        if session not in full_config['sso_sessions']:
            raise SystemExit(
                f"unknown sso-session '{session}' — available: {', '.join(sorted(full_config['sso_sessions']))}"
            )
        cmd_login(session)
    elif args.cmd == 'switch':
        cmd_switch(current)
    elif args.cmd == 'refresh':
        target = args.profile or current
        cmd_refresh(target, _session_in_context(current, full_config, args.session), full_config)
    elif args.cmd == 'add':
        cmd_add(_session_in_context(current, full_config, args.session), args.profile, full_config)
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

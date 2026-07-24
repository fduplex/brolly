"""Self-contained shell-prompt pill — the `brolly ps1` command.

This runs on **every** shell prompt, so it is deliberately stdlib-only and never imports boto3 (that alone costs
~70ms; this module renders in ~10ms). It reads local files only: the AWS config, plus one small token-expiry file.
No network, no keychain access, no `aws` invocation.

Freshness comes from whichever store the profile actually uses — the non-secret expiry sidecar for secure-mode
profiles, or the stock plaintext token cache otherwise.
"""

import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

type State = str  # one of: live, idle, gone, plain

_AWS = '\ue7ad'  # nf-dev-aws
_POWERLINE = '\ue0b0'  # nf-pl-left_hard_divider
_CLOCK = '\uf017'  # nf-fa-clock_o
_CROSS = '\uf00d'  # nf-fa-times

# 256-colour codes. _ACCENT is the warm tone the pill is built around — change it here and the live background
# and idle text follow together. _ALERT is its desaturated red counterpart, picked to sit at the same weight.
_ACCENT = 173  # muted terracotta (#d7875f)
_ALERT = 167  # muted red (#d75f5f)
_SHOULDER = 238  # dark grey the leading glyph sits on
_LOGO = 255  # near-white (#eeeeee) — tinting the AWS glyph with _ACCENT made it vanish against _SHOULDER

# state -> (background colour, foreground colour, leading glyph)
_STYLES: dict[State, tuple[int, int, str]] = {
    'live': (_ACCENT, 236, ''),  # terracotta — creds are live
    'idle': (240, _ACCENT, f'{_CLOCK} '),  # grey clock — lapsed, refreshes on next use
    'gone': (_ALERT, 231, f'{_CROSS} '),  # red cross — no token, run brolly
    'plain': (_SHOULDER, 250, ''),  # not an SSO profile
}


def _aws_config_path() -> Path:
    return Path(os.environ.get('AWS_CONFIG_FILE') or Path.home() / '.aws' / 'config')


def _read_profile(profile: str, config: Path) -> tuple[str | None, str | None, bool]:
    """Scan the config for one profile: returns (sso_session, account label, is-secure-mode)."""
    session: str | None = None
    account_name: str | None = None
    account_id: str | None = None
    secure = False
    try:
        text = config.read_text()
    except OSError:
        return None, None, False

    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('['):
            in_section = stripped == f'[profile {profile}]'
            continue
        if not in_section or '=' not in line:
            continue
        key, _, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if key == 'sso_session':
            session = value
        elif key == 'sso_account_name':
            account_name = value
        elif key in ('sso_account_id', 'brolly_sso_account_id'):
            account_id = value
        elif key == 'credential_process' and 'brolly' in value:
            secure = True
    return session, account_name or account_id, secure


def _expiry_path(session: str, config: Path, secure: bool) -> Path:
    """Where this profile's freshness lives: the secure-mode sidecar, else botocore's plaintext token cache."""
    key = hashlib.sha1(session.encode('utf-8')).hexdigest()
    if secure:
        return config.parent / 'brolly' / f'{key}.json'
    return Path.home() / '.aws' / 'sso' / 'cache' / f'{key}.json'


def _state_for(path: Path) -> State:
    """live if the cached token is still valid, idle if it lapsed (refreshes on next use), gone if absent."""
    try:
        expires_at = json.loads(path.read_text())['expiresAt']
    except OSError, ValueError, KeyError:
        return 'gone' if not path.is_file() else 'idle'
    try:
        expiry = datetime.fromisoformat(expires_at)
    except ValueError:
        return 'idle'
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    return 'live' if expiry > datetime.now(UTC) else 'idle'


def _render(profile: str, session: str | None, account: str | None, state: State) -> str:
    """The powerline pill. \\001/\\002 wrap non-printing bytes so readline computes the prompt width correctly."""
    background, foreground, glyph = _STYLES[state]
    start, end, esc = '\001', '\002', '\033'
    handle = f'{session}/{profile}' if session else profile
    label = f'{handle} · {account}' if account else handle
    return (
        f'{start}{esc}[48;5;{_SHOULDER};38;5;{_LOGO};1m{end} {_AWS} '
        f'{start}{esc}[38;5;{_SHOULDER};48;5;{background}m{end}{_POWERLINE}'
        f'{start}{esc}[48;5;{background};38;5;{foreground};1m{end} {glyph}{label} '
        f'{start}{esc}[0;38;5;{background}m{end}{_POWERLINE}'
        f'{start}{esc}[0m{end} '
    )


def main() -> int:
    """Print the pill for $AWS_PROFILE, or nothing at all when no profile is set."""
    profile = os.environ.get('AWS_PROFILE')
    if not profile:
        return 0

    config = _aws_config_path()
    session, account, secure = _read_profile(profile, config)
    state: State = 'plain' if not session else _state_for(_expiry_path(session, config, secure))
    sys.stdout.write(_render(profile, session, account, state))
    return 0

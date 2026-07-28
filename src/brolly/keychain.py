"""Opt-in OS-keychain token storage for brolly.

By default brolly is a thin layer over the stock plaintext ``~/.aws/sso/cache``. This module implements the
opt-in *secure* mode: the SSO token blob lives in the OS keychain (via `keyring`), brolly registers itself as
each profile's ``credential_process``, and a small non-secret expiry sidecar keeps the shell-prompt freshness
check cheap and network-free.

Why the profile is reshaped the way it is: botocore's credential resolver runs its SSO provider *before* the
``credential_process`` provider, and the SSO provider activates whenever ``sso_account_id`` and ``sso_role_name``
are present. Leaving those keys would make botocore read the (now-empty) plaintext cache and fail instead of
falling through to ``credential_process``. So a secured profile drops the standard account/role keys, stores
them under ``brolly_sso_*`` instead, and keeps ``sso_session`` — which the *token* provider still needs to
refresh, but which alone does not activate the credential SSO provider.
"""

import json
import os
import re
import shlex
import shutil
import sys
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from hashlib import sha1
from pathlib import Path
from time import sleep
from types import ModuleType
from typing import Any, NamedTuple

import boto3
import botocore.session
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ProfileNotFound, SSOTokenLoadError, TokenRetrievalError, UnauthorizedSSOTokenError
from botocore.tokens import SSOTokenProvider

from .cli import (
    AccessToken,
    AccountId,
    AwsConfig,
    ProfileName,
    Region,
    RoleName,
    SessionName,
    _atomic_write,
    _aws,
    _aws_config_path,
    _aws_dir,
    _config_path,
    _create_profile_skeleton,
    _ensure_brolly_dir,
    _is_secure,
    _pick_account_role,
    _read_config,
    _record_secured_session,
    _report_added,
    _session_profiles,
    _write_config,
)

type TokenBlob = dict[str, Any]

_KEYRING_SERVICE = 'brolly-sso'
_DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'
_REFRESH_GRANT = 'refresh_token'
_CLIENT_NAME = 'brolly'

# The scope brolly's own registration always asks for: listing accounts and roles and vending credentials all
# require it, so it is never optional here. It is registered alongside the refresh_token grant — which is what
# lets botocore's token provider renew a session without a browser, and what the blob needs a refreshToken for.
_ACCOUNT_SCOPE = 'sso:account:access'

_NO_KEYRING_BACKEND = (
    'no OS keychain backend is available, so brolly cannot store tokens securely.\n'
    '  • macOS: the system Keychain works out of the box.\n'
    '  • Desktop Linux (GNOME/KDE): start/unlock gnome-keyring or KWallet inside a D-Bus session.\n'
    '  • Linux without a desktop: use pass + gpg-agent (recommended, bundled) —\n'
    '        sudo apt install pass && pass init <gpg-key-id>\n'
    '        brolly secure enable --backend keyring_pass.PasswordStoreBackend\n'
    'Pass any keyring backend explicitly with --backend <dotted.path>. '
    'See https://pypi.org/project/keyring for the backend list.'
)


_BACKEND_LABELS = {
    'keyring.backends.macOS': 'macOS Keychain',
    'keyring.backends.SecretService': 'Secret Service (GNOME Keyring / KWallet)',
    'keyring.backends.kwallet': 'KWallet',
    'keyring.backends.Windows': 'Windows Credential Locker',
    'keyring_pass': 'pass (gpg-agent)',
    'keyrings.alt.file': 'encrypted file (keyrings.alt)',
}


def _import_keyring() -> ModuleType:
    import keyring

    return keyring


def _is_fail_backend(keyring_module: ModuleType) -> bool:
    import keyring.backends.fail

    return isinstance(keyring_module.get_keyring(), keyring.backends.fail.Keyring)


def _select_backend(keyring_module: ModuleType, backend: str) -> None:
    """Force a specific keyring backend by dotted path, or exit cleanly if it can't be loaded here."""
    from keyring.core import load_keyring

    try:
        keyring_module.set_keyring(load_keyring(backend))
    except Exception as x:
        raise SystemExit(
            f"keyring backend '{backend}' could not be loaded in brolly's environment: {x}\n"
            'Install it where brolly runs, e.g.  uv tool install brolly --with <backend-package>  '
            '(or  pipx inject brolly <backend-package>).'
        ) from None


def _configured_keyring() -> ModuleType:
    """Return `keyring` with brolly's saved backend applied — no dependence on ``PYTHON_KEYRING_BACKEND``."""
    keyring_module = _import_keyring()
    backend = _read_config().get('keyring_backend')
    if backend:
        _select_backend(keyring_module, backend)
    if _is_fail_backend(keyring_module):
        raise SystemExit(_NO_KEYRING_BACKEND)
    return keyring_module


def _pass_store_ready() -> bool:
    """True if the `pass` CLI and an initialized store are both present — i.e. ``keyring_pass`` will actually work."""
    if shutil.which('pass') is None:
        return False
    store = os.environ.get('PASSWORD_STORE_DIR') or (Path.home() / '.password-store')
    return (Path(store) / '.gpg-id').is_file()


def _autodetect_backend(keyring_module: ModuleType) -> str | None:
    """The backend to use when none is configured: a working OS keychain if present, else pass if its store is ready.

    keyring's own auto-detection ranks ``keyring_pass`` below the OS keychains and only when its store initializes,
    so we prefer any real OS keychain and fall back to probing for pass ourselves — which reliably picks it up on a
    desktop-less Linux box without the user having to name the backend.
    """
    if not _is_fail_backend(keyring_module):
        active = type(keyring_module.get_keyring())
        return f'{active.__module__}.{active.__name__}'
    if _pass_store_ready():
        return 'keyring_pass.PasswordStoreBackend'
    return None


def _backend_label(keyring_module: ModuleType) -> str:
    """A human-friendly name for the active keyring backend, for transparency in ``secure`` output."""
    backend = type(keyring_module.get_keyring())
    return _BACKEND_LABELS.get(backend.__module__, f'{backend.__module__}.{backend.__name__}')


def _cache_key(session_name: SessionName) -> str:
    """botocore's SSO token cache key: the SHA1 of the session name (matches ``~/.aws/sso/cache`` naming)."""
    return sha1(session_name.encode('utf-8')).hexdigest()


def _iso(value: object) -> str:
    return value.isoformat() if isinstance(value, datetime) else str(value)


def _json_default(obj: object) -> str:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f'not JSON serializable: {type(obj).__name__}')


def _sidecar_path(cache_key: str) -> Path:
    return _aws_dir() / 'brolly' / f'{cache_key}.json'


def _write_sidecar(session_name: SessionName, cache_key: str, expires_at: object, refreshable: bool) -> None:
    """Persist the non-secret expiry alongside the config so the prompt pill never touches the keychain.

    ``refreshable`` mirrors whether the stored blob carries a refresh token — the one fact that separates a token
    that renews silently from one that ends in a browser, and the only way `ls` can tell without a keychain read.
    """
    _ensure_brolly_dir()
    _atomic_write(
        _sidecar_path(cache_key),
        json.dumps({'session': session_name, 'expiresAt': _iso(expires_at), 'refreshable': refreshable}),
    )


def _remove_sidecar(cache_key: str) -> None:
    _sidecar_path(cache_key).unlink(missing_ok=True)


def _sso_cache_dir() -> Path:
    """The stock plaintext SSO cache — botocore's fixed ``~/.aws/sso/cache``, and the AWS CLI's directory, not ours."""
    return Path.home() / '.aws' / 'sso' / 'cache'


def _plaintext_token_path(session_name: SessionName) -> Path:
    """The stock plaintext SSO token file for a session — botocore's fixed ``~/.aws/sso/cache`` location."""
    return _sso_cache_dir() / f'{_cache_key(session_name)}.json'


def _read_cache_json(path: Path) -> Any:
    """One file from ~/.aws/sso/cache decoded as JSON, or None if it will not decode as any.

    That directory belongs to the AWS CLI and may hold anything — a half-written file, a stray note, a directory
    someone put there. A file brolly cannot read is a file brolly must never act on, so the failure is a value
    rather than an exception: nothing here is worth crashing a purge over.
    """
    try:
        return json.loads(path.read_text())
    except OSError, ValueError:
        return None


_REGISTRATION_KEYS = frozenset({'clientId', 'clientSecret', 'expiresAt'})


def _is_registration_blob(data: Any) -> bool:
    """True if a parsed cache file is an OIDC client registration rather than a token blob or something else.

    The AWS CLI writes a registration as exactly ``clientId``, ``clientSecret`` and ``expiresAt``, plus ``scopes``
    (and ``grantTypes`` on the authorization-code flow) — no startUrl, no region, no session name. So its shape
    says *what* a file is and never *whose* it is; saying whose is what ``_session_registrations`` is for.
    ``accessToken`` is the token blob's own key, and testing for its absence is what stops this ever matching one:
    a token blob carries a clientId too, because the CLI caches the registration alongside it.
    """
    return isinstance(data, dict) and 'accessToken' not in data and data.keys() >= _REGISTRATION_KEYS


def _registration_cache_key(session_name: SessionName, sso_config: AwsConfig) -> str | None:
    """The file name `aws sso login` gives this session's client registration, or None if brolly cannot know it.

    Quoted from the AWS CLI v2's ``BaseSSOTokenFetcher._registration_cache_key`` (awscli/botocore/utils.py)::

        args = {
            'tool': 'botocore',
            'startUrl': start_url,
            'region': self._sso_region,
            'scopes': scopes,
            'session_name': session_name,
        }
        cache_args = json.dumps(args, sort_keys=True).encode('utf-8')
        return hashlib.sha1(cache_args).hexdigest()

    ``scopes`` is the sso-session's ``sso_registration_scopes`` put through the CLI's own
    ``parse_sso_registration_scopes`` — comma-split, stripped, empties dropped — and None, not ``[]``, when the key
    is absent entirely. Not brolly's ``_registration_scopes``, which unions in the account scope brolly's own
    registration needs: this has to be what the AWS CLI passed, not what brolly would have.

    Which is also why this is only half an answer. The hash is a function of config that may have changed since
    the login that wrote the file, and a stale ``sso_registration_scopes`` yields a name that matches nothing.
    ``_session_registrations`` therefore treats it as one route among two, never as the identification.
    """
    start_url, region = sso_config.get('sso_start_url'), sso_config.get('sso_region')
    if not (start_url and region):
        return None
    raw_scopes = sso_config.get('sso_registration_scopes')
    scopes = None if raw_scopes is None else [s.strip() for s in raw_scopes.split(',') if s.strip()]
    args = {
        'tool': 'botocore',
        'startUrl': start_url,
        'region': region,
        'scopes': scopes,
        'session_name': session_name,
    }
    return sha1(json.dumps(args, sort_keys=True).encode('utf-8')).hexdigest()


def _token_client_id(session_name: SessionName) -> str | None:
    """The ``clientId`` in this session's plaintext token blob — the name of the registration that minted it."""
    blob = _read_cache_json(_plaintext_token_path(session_name))
    client_id = blob.get('clientId') if isinstance(blob, dict) else None
    return client_id if isinstance(client_id, str) else None


def _session_registrations(session_name: SessionName, sso_config: AwsConfig) -> list[Path]:
    """The OIDC client registrations in ~/.aws/sso/cache that are provably this session's.

    `aws sso login` writes two credentials, not one: the token blob, and the client registration it was minted
    under — a clientId/clientSecret pair with roughly a 90-day life. Secure mode leaves nothing of the session's
    in that directory, but deleting somebody else's registration is a worse failure than leaving one behind, so a
    file is only ever taken on one of two positive attributions, and one matched by neither is left alone:

    - **the token blob names it.** The CLI copies the registration's clientId and clientSecret into the token it
      writes ("Cache the registration alongside the token" — botocore/tokens.py), so a registration whose clientId
      is the one in *this* session's token blob is the registration that minted it. This is the route that matters
      in practice: what brolly purges is a leaked token blob, and the blob identifies its own registration.
    - **the name is reproducible.** See ``_registration_cache_key``: a file under that exact name which reads as a
      registration is this session's by construction. It is the only route left once the token blob is gone, and
      it holds only while ``sso_registration_scopes`` is what it was at login time.

    Neither route can reach a token blob, this session's or another's — ``_is_registration_blob`` excludes anything
    carrying an ``accessToken``. brolly's own ``_device_login`` caches no registration to disk, so every file this
    finds is an `aws sso login` leftover.
    """
    found: dict[Path, None] = {}  # an ordered set: the two routes can name the same file
    cache_key = _registration_cache_key(session_name, sso_config)
    if cache_key is not None:
        by_name = _sso_cache_dir() / f'{cache_key}.json'
        if _is_registration_blob(_read_cache_json(by_name)):
            found[by_name] = None
    client_id = _token_client_id(session_name)
    if client_id is not None:
        for candidate in sorted(_sso_cache_dir().glob('*.json')):
            data = _read_cache_json(candidate)
            if _is_registration_blob(data) and data['clientId'] == client_id:
                found[candidate] = None
    return list(found)


class _Leftovers(NamedTuple):
    """What ~/.aws/sso/cache still holds for one session: its token blob, and every client registration in that
    directory brolly can positively attribute to it."""

    token: Path | None
    registrations: list[Path]

    @property
    def paths(self) -> list[Path]:
        """Every file, token first — the order they are reported and removed in."""
        return [*([self.token] if self.token is not None else []), *self.registrations]

    @property
    def phrase(self) -> str:
        """How to name what is on disk inside a sentence. The two files are different credentials with different
        lives, and a message that called a client registration a "token" would send the reader to the wrong file."""
        parts = ['its token'] if self.token is not None else []
        if self.registrations:
            parts.append('the OIDC client registration `aws sso login` cached with it')
        return ' and '.join(parts)


def _sso_session_config(session_name: SessionName, full_config: AwsConfig | None) -> AwsConfig:
    """The sso-session's own config block, or an empty one. A caller with no ``full_config`` to hand loses only the
    reproducible-name route to a registration (see ``_session_registrations``), never the token."""
    return (full_config or {}).get('sso_sessions', {}).get(session_name, {})


def _plaintext_leftovers(session_name: SessionName, sso_config: AwsConfig) -> _Leftovers:
    """Everything in ~/.aws/sso/cache that is provably this session's — and nothing that is merely near it."""
    token = _plaintext_token_path(session_name)
    return _Leftovers(token if token.is_file() else None, _session_registrations(session_name, sso_config))


def _unlink_cache_file(path: Path, what: str) -> bool:
    """Delete one file from ~/.aws/sso/cache. True if a file was there and went."""
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError as x:
        # something we cannot delete must still not break the command that noticed it — report and carry on
        print(f'! could not remove the plaintext {what} {path}: {x}', file=sys.stderr)
        return False
    return True


def _remove_plaintext_token(session_name: SessionName) -> bool:
    """Delete the now-redundant plaintext SSO token (it lives in the keychain now). True if a file was removed."""
    return _unlink_cache_file(_plaintext_token_path(session_name), 'token cache')


def _remove_leftovers(session_name: SessionName, leftovers: _Leftovers) -> None:
    """Delete what was attributed to the session, naming each file — silence would hide that a credential was on
    disk. Takes an already-computed ``_Leftovers`` because the token blob is what identifies its own registration:
    read the directory first, delete second, or the second file loses the only thing that pointed at it."""
    if leftovers.token is not None and _unlink_cache_file(leftovers.token, 'token cache'):
        print(f"✓ removed plaintext token cache for session '{session_name}'", file=sys.stderr)
    for path in leftovers.registrations:
        if _unlink_cache_file(path, 'client registration'):
            print(
                f"✓ removed the OIDC client registration `aws sso login` cached for session '{session_name}' — a "
                f"client secret with a ~90-day life, and brolly's own login registers its own client",
                file=sys.stderr,
            )


def _stock_profiles(session_name: SessionName, full_config: AwsConfig) -> list[ProfileName]:
    """Profiles under the session still carrying both stock SSO keys — botocore resolves those from the plaintext
    blob, and they are exactly the set ``_reshape_session_profiles`` converts, so what healing fixes is what this
    reports."""
    return sorted(
        p for p, c in _session_profiles(session_name, full_config) if c.get('sso_account_id') and c.get('sso_role_name')
    )


# A private, synthetic key ``_reshape_session_profiles`` stashes onto the caller's ``full_config`` dict — never a
# real botocore config concept, never written to disk. See ``_note_reshape_failures`` for why it has to exist.
_RESHAPE_FAILURES_KEY = '_brolly_reshape_failures'


def _note_reshape_failures(full_config: AwsConfig, session_name: SessionName, failed: list[ProfileName]) -> None:
    """Record, on the caller's own ``full_config``, which profiles the reshape just run could not convert.

    ``_stock_profiles`` cannot be trusted to notice this on its own: a profile whose section header confuses `aws
    configure set` ends up with a *second* section that shadows the first, and botocore then resolves the profile
    entirely from that second section — dropping ``sso_session`` along with the stock keys. ``_secure_profile``
    already overwrote this profile's entry in ``full_config`` with that very (now key-less) reading, so by the time
    anything downstream looks, the profile has become invisible to ``_session_profiles`` under this session, stock
    keys included. The only way to hold the purge back is to have said so at the one moment the fact was still
    known: right here, right after the reshape that discovered it.
    """
    full_config[_RESHAPE_FAILURES_KEY] = {**full_config.get(_RESHAPE_FAILURES_KEY, {}), session_name: list(failed)}


def _reshape_failures(session_name: SessionName, full_config: AwsConfig | None) -> list[ProfileName]:
    """Profiles the most recent reshape of this exact ``full_config`` failed to convert, if any.

    ``None`` (a caller with nothing reshaped) and a plain dict freshly loaded from disk both answer "none" — only a
    ``full_config`` that a reshape has actually run over and mutated in place can carry this, which is exactly the
    set of callers this needs to affect.
    """
    if full_config is None:
        return []
    return full_config.get(_RESHAPE_FAILURES_KEY, {}).get(session_name, [])


def purge_session_plaintext(session_name: SessionName, full_config: AwsConfig | None = None) -> None:
    """Clear what a secured session left in ~/.aws/sso/cache — its token blob, and the OIDC client registration
    `aws sso login` cached beside it — whether or not this command authenticated. ``cli`` runs this from the one
    place that decides a session is secure, so no command can forget it.

    Every purge comes through here, a completed device login included. A fresh keychain token makes the blob stale
    for brolly, but a stock profile cannot read the keychain at all — for that profile the blob is still the only
    credential there is, and deleting it on the strength of a login it cannot use locks the user out until the next
    `aws sso login`. So no path may delete these files while any profile under the session still resolves from
    them, and no path may delete them before healing has had its chance to remove the last such reader.

    Two guards, both stated rather than silent, and neither a replacement for the other:

    - while a stock profile is still configured under the session, botocore resolves *its* credentials out of this
      very blob, and deleting it would break a working profile with nothing but a browser login to get it back.
      ``cli._enter_secure_session`` and `secure enable` both heal those profiles before they purge, so this guard
      fires for them only on a profile healing could not convert.
    - a profile a reshape just failed to convert may not even trip the guard above — see
      ``_note_reshape_failures`` for the shadowed-section case that makes it invisible to ``_stock_profiles``
      entirely — so a failed reshape holds the purge back on its own account, unconditionally.

    Neither guard stands for ``cmd_credential_process`` any more: that path reports and never deletes at all, so
    it does not come through here — see ``report_session_plaintext``.
    """
    leftovers = _plaintext_leftovers(session_name, _sso_session_config(session_name, full_config))
    if not leftovers.paths:
        return  # the common case, and its whole cost: three lookups that miss on files which are not there
    if stock := _stock_profiles(session_name, full_config or botocore.session.Session().full_config):
        print(
            f"! session '{session_name}' is secured, but ~/.aws/sso/cache still holds {leftovers.phrase} — "
            f'{", ".join(stock)} still resolves credentials from it, so this command left it alone.\n'
            f'  Convert it and clear the file:  brolly secure enable -s {session_name}',
            file=sys.stderr,
        )
        return
    if failed := _reshape_failures(session_name, full_config):
        print(
            f"! session '{session_name}' is secured, but ~/.aws/sso/cache still holds {leftovers.phrase} — "
            f'{", ".join(failed)} just failed to convert to secure mode, so this command deliberately left the '
            f'plaintext token in place rather than delete a blob that profile may still need.\n'
            f'  Fix the profile (see the error reported above), then re-run:  brolly secure enable -s {session_name}',
            file=sys.stderr,
        )
        return
    _remove_leftovers(session_name, leftovers)


def report_session_plaintext(session_name: SessionName, full_config: AwsConfig) -> None:
    """Name what ~/.aws/sso/cache still holds for a secured session, and remove nothing at all.

    ``cmd_credential_process``'s counterpart to ``purge_session_plaintext``, and a separate function rather than a
    parameter on it: this is the one caller that must never touch the filesystem, and a flag whose default deletes
    is exactly the kind of thing a later edit gets backwards at a call site. It also has no use for the purge's two
    guards, which decide *whether* to delete — nothing here is conditional, because nothing here is destructive.

    Why it reports rather than purges. `credential-process` is spawned by the SDK on every cold credential
    resolution, non-interactively, and the purge's guards only recognise consumers that exist as AWS profiles: a
    third-party SSO helper, a script, a container mount reading that blob is invisible to them, so deleting it here
    could silently break a consumer brolly cannot see. Every interactive path still purges, so the leak closes the
    next time the user runs a brolly command — which the message says, so nobody reads this as brolly ignoring it.

    Everything goes to stderr. stdout carries the credential JSON the calling SDK parses, and a stray byte on it
    breaks the process this is supposed to be serving.
    """
    leftovers = _plaintext_leftovers(session_name, _sso_session_config(session_name, full_config))
    if not leftovers.paths:
        return
    listed = '\n'.join(f'      {path}' for path in leftovers.paths)
    print(
        f"! session '{session_name}' is secured, but ~/.aws/sso/cache still holds {leftovers.phrase}:\n"
        f'{listed}\n'
        f'  credential-process only reports this: it runs unattended for whatever spawned it, so it will not '
        f'delete a file another tool may still be reading.\n'
        f'  The next brolly command clears it, or clear it now:  brolly secure enable -s {session_name}',
        file=sys.stderr,
    )


def _keychain_failures(keyring_module: ModuleType) -> tuple[type[BaseException], ...]:
    """What "the keychain will not answer" is raised as — which is not one class, whatever `keyring` documents.

    ``KeyringError`` is the contract, and the backends do not all keep it: ``keyring_pass`` raises a bare
    ``RuntimeError`` when gpg-agent refuses to unlock. That is brolly's own recommendation for a desktop-less Linux
    box (see ``_NO_KEYRING_BACKEND``) failing in precisely the way `secure disable` exists to get the user out of,
    so a taxonomy naming only ``KeyringError`` tracebacks on the path that most needs to degrade cleanly. Widened
    to these two and no further: a locked keychain is a specific condition, not "anything went wrong".
    """
    return (keyring_module.errors.KeyringError, RuntimeError)


def _keyring_call(keyring_module: ModuleType, operation: Any, *args: str) -> Any:
    """Run a keyring operation, turning any backend failure into a clean exit rather than a traceback."""
    try:
        return operation(*args)
    except _keychain_failures(keyring_module) as x:
        raise SystemExit(f'OS keychain access failed: {x}') from None


@contextmanager
def _quiet_stderr() -> Any:
    """Silence fd-level stderr for a keyring read: the `pass` backend prints "not in the password store" on a
    normal cache miss, which is noise, not an error. Suppresses only the wrapped call — exceptions we raise
    afterward still reach the (restored) terminal."""
    saved = os.dup(2)
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, 2)
        yield
    finally:
        os.dup2(saved, 2)
        os.close(devnull)
        os.close(saved)


def _prove_keychain(keyring_module: ModuleType, session_name: SessionName) -> None:
    """Do one real keychain operation — a read of the session's own entry, hit or miss — and let its SystemExit out.

    Loading a backend is not the same as being able to use one: a saved backend whose package is gone, or a `pass`
    store whose gpg-agent cannot unlock headless, only fails on the first real operation. Takes the module rather
    than resolving one, because ``secure enable`` must prove a backend it has not saved yet — see
    ``cmd_secure_enable``, which cannot ask ``_configured_keyring`` for the backend it is in the middle of choosing.
    """
    with _quiet_stderr():
        _keyring_call(keyring_module, keyring_module.get_password, _KEYRING_SERVICE, _cache_key(session_name))


def preflight_keychain(session_name: SessionName) -> ModuleType:
    """Prove the keychain is reachable *before* a caller mutates anything on the strength of it.

    Resolves brolly's saved backend and proves it with ``_prove_keychain``, so the failure of a backend that loads
    but cannot answer surfaces while ~/.aws is still untouched.
    """
    keyring_module = _configured_keyring()
    _prove_keychain(keyring_module, session_name)
    return keyring_module


class _KeychainTokenCache:
    """Dict-like SSO token cache backed by the OS keychain — a drop-in for botocore's ``JSONFileCache``.

    botocore's ``SSOTokenProvider`` treats its cache as ``key -> token-blob`` and writes back through it on every
    refresh, so backing that interface with `keyring` gives us silent refresh-token rotation for free. Each write
    also refreshes the non-secret expiry sidecar.
    """

    def __init__(self, keyring_module: ModuleType, session_name: SessionName) -> None:
        self._keyring = keyring_module
        self._session_name = session_name

    def _run(self, operation: Any, *args: str) -> Any:
        return _keyring_call(self._keyring, operation, *args)

    def __contains__(self, cache_key: str) -> bool:
        with _quiet_stderr():
            return self._run(self._keyring.get_password, _KEYRING_SERVICE, cache_key) is not None

    def __getitem__(self, cache_key: str) -> TokenBlob:
        with _quiet_stderr():
            raw = self._run(self._keyring.get_password, _KEYRING_SERVICE, cache_key)
        if raw is None:
            raise KeyError(cache_key)
        return json.loads(raw)

    def __setitem__(self, cache_key: str, value: TokenBlob) -> None:
        self._run(self._keyring.set_password, _KEYRING_SERVICE, cache_key, json.dumps(value, default=_json_default))
        _write_sidecar(self._session_name, cache_key, value.get('expiresAt'), 'refreshToken' in value)

    def _delete(self, cache_key: str) -> None:
        """Delete raw, translating only "no such entry" — every other backend failure is left to ``_run``."""
        try:
            self._keyring.delete_password(_KEYRING_SERVICE, cache_key)
        except self._keyring.errors.PasswordDeleteError:
            raise KeyError(cache_key) from None

    def __delitem__(self, cache_key: str) -> None:
        """Drop the token and the sidecar describing it — the sidecar goes even when the entry was already absent,
        or an interrupted disable leaves `ls` reading an expiry for a secret that no longer exists."""
        try:
            self._run(self._delete, cache_key)
        finally:
            _remove_sidecar(cache_key)


_SECTION_HEADER = re.compile(r'\[(?P<header>.+)\]')


def _header_profile(line: str) -> ProfileName | None:
    """The profile a section header names, or None — resolved exactly as botocore resolves it.

    Anything narrower silently misses sections botocore honours, and a missed section means the stock SSO keys
    survive a conversion. configparser's header pattern is greedy and unanchored (so a trailing comment is not part
    of the name), it never strips the captured header (so ``[ default ]`` is *not* the default profile), and
    botocore then ``shlex.split``s it — which collapses repeated whitespace and unquotes quoted names.
    """
    match = _SECTION_HEADER.match(line.strip())
    if match is None:
        return None
    header = match.group('header')
    if header == 'default':
        return 'default'
    if not header.startswith('profile'):
        return None
    try:
        parts = shlex.split(header)
    except ValueError:
        return None
    return parts[1] if len(parts) == 2 else None


_OPTION_DELIMITERS = ('=', ':')


def _option_name(line: str) -> str | None:
    """The option a line names, or None if it names none — configparser accepts ``:`` as well as ``=``.

    Splitting on ``=`` alone leaves a hand-written ``sso_account_id: 123`` in place, which botocore reads exactly
    like the ``=`` form: the SSO credential provider goes on activating on a profile brolly has just called
    secured. Whichever delimiter comes first is the one configparser uses, so this reads the same key it does.
    """
    positions = [line.index(delimiter) for delimiter in _OPTION_DELIMITERS if delimiter in line]
    return line[: min(positions)].strip().lower() if positions else None


def _config_remove_keys(profile: ProfileName, keys: set[str]) -> None:
    """Delete specific ``key = value`` lines from a profile section, preserving the rest of the file verbatim.

    ``aws configure set`` can only add or blank keys, and a blanked ``sso_account_id =`` still counts as present
    to botocore — so removing the SSO credential-provider trigger has to be done at the line level. Line level and
    not a configparser round-trip: that would rewrite the user's whole config, dropping their comments, blank lines
    and key ordering as a side effect of deleting two lines.
    """
    path = _aws_config_path()
    if not path.is_file():
        return
    wanted = {key.lower() for key in keys}  # configparser lowercases option names, so the file's casing is free
    out: list[str] = []
    in_section = False
    for line in path.read_text().splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith('['):
            in_section = _header_profile(stripped) == profile
        elif in_section and _option_name(line) in wanted:
            continue
        out.append(line)
    _atomic_write(path, ''.join(out))


def _profile_on_disk(profile: ProfileName) -> AwsConfig:
    """Re-read one profile straight from ~/.aws/config — the only way to know a line-level removal actually landed."""
    return botocore.session.Session().full_config['profiles'].get(profile, {})


def _brolly_credential_process(profile: ProfileName) -> str:
    """The ``credential_process`` a secured profile carries: brolly re-entered for this profile by the calling SDK."""
    return f'brolly credential-process --profile {profile}'


def _is_brolly_credential_process(command: str) -> bool:
    """True if a ``credential_process`` value is brolly's own — the key secure mode has to own to work at all.

    Matched on the command rather than by string equality with what ``_brolly_credential_process`` writes: the same
    helper spelled with a path or a runner (``/usr/local/bin/brolly credential-process …``, ``uv run brolly
    credential-process …``) is still brolly holding the key, and calling those a conflict would be a conflict
    brolly invented. Anything else — any value that does not run brolly's own subcommand — is somebody else's
    credential helper, and secure mode does not get to overwrite it.
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    return 'credential-process' in parts and any(Path(part).name == 'brolly' for part in parts)


def _secure_profile(
    profile: ProfileName,
    account_id: AccountId,
    role: RoleName,
    account_name: str | None,
    cfg: AwsConfig | None = None,
) -> bool:
    """Rewrite one profile into secure shape: add ``credential_process`` + ``brolly_sso_*``, drop the SSO trigger.

    Returns whether the profile really is secure now, and says why whenever that is no. Two ways it can be no, one
    checked before anything is written and one read back after:

    - the profile already has a ``credential_process`` brolly did not write. Secure mode genuinely needs that key
      — it *is* how a secured profile gets credentials — but a user's own helper is not brolly's to destroy, so a
      foreign value is a conflict to report, not a line to overwrite. Nothing is mutated on that path; the profile
      stays stock, which is also what holds the session's plaintext token back (see ``purge_session_plaintext``).
    - the removal is a line edit against a file botocore parses more liberally than any matcher of ours, so its
      result is read back rather than assumed: a profile that kept its stock keys still resolves out of
      ~/.aws/sso/cache, and reporting it as converted would license deleting the very blob it reads.

    ``cfg`` is this profile's entry in a caller's already-loaded ``full_config``; passing it replaces that
    in-memory copy with what is now on disk, so nothing downstream in the same command works off a false premise.
    """
    existing: str | None = _profile_on_disk(profile).get('credential_process')
    if existing and not _is_brolly_credential_process(existing):
        print(
            f"! '{profile}' already has a credential_process brolly did not write, so it was left exactly as it "
            f'is and not converted:\n'
            f'      credential_process = {existing}\n'
            f"  Secure mode has to own that key, so brolly treats another tool's helper as a conflict rather than "
            f'overwriting it. Remove or repoint that line to convert this profile; until then it goes on resolving '
            f"from ~/.aws/sso/cache, and the session's plaintext token stays on disk with it.",
            file=sys.stderr,
        )
        return False

    command = _brolly_credential_process(profile)
    _aws('configure', 'set', 'credential_process', command, '--profile', profile)
    _aws('configure', 'set', 'brolly_sso_account_id', account_id, '--profile', profile)
    _aws('configure', 'set', 'brolly_sso_role_name', role, '--profile', profile)
    if account_name:
        _aws('configure', 'set', 'sso_account_name', account_name, '--profile', profile)
    _config_remove_keys(profile, {'sso_account_id', 'sso_role_name'})

    on_disk = _profile_on_disk(profile)
    if cfg is not None:
        cfg.clear()
        cfg.update(on_disk)
    if on_disk.get('sso_account_id') or on_disk.get('sso_role_name'):
        print(
            f"! '{profile}' still carries sso_account_id/sso_role_name in {_aws_config_path()} after brolly tried "
            f'to remove them, so it goes on resolving credentials from ~/.aws/sso/cache and brolly will not treat '
            f'it as secured.\n'
            f'  Delete those two lines from its section by hand, then re-run the command.',
            file=sys.stderr,
        )
        return False
    missing = [key for key in ('sso_session', 'credential_process', 'brolly_sso_role_name') if key not in on_disk]
    if missing:
        print(
            f"! '{profile}' is not in secure shape after the rewrite — read back from {_aws_config_path()} it is "
            f'missing {", ".join(missing)}.\n'
            f'  `aws configure set` matches section headers more strictly than botocore reads them, so an unusual '
            f'header (a trailing comment, a quoted or oddly spaced name) makes it write a second [profile '
            f'{profile}] section that shadows the first. Merge the two by hand, then re-run the command.',
            file=sys.stderr,
        )
        return False
    return True


class _Reshaped(NamedTuple):
    """One pass over a session's profiles: those rewritten into secure shape just now, those already in it, those
    carrying no account/role to move, and those whose stock keys survived the rewrite."""

    converted: list[ProfileName]
    already: list[ProfileName]
    skeletons: list[ProfileName]
    failed: list[ProfileName]


def _reshape_session_profiles(session_name: SessionName, full_config: AwsConfig) -> _Reshaped:
    """Rewrite every stock profile under the session into secure shape — the pass `secure enable` and healing share.

    Keyed on the stock keys, never on the absence of ``brolly_sso_*``: a profile can carry both shapes at once (an
    interrupted conversion, a hand-edited config), and while it does, botocore's SSO credential provider still
    activates on the stock pair. Treating it as already secure would leave it reading the plaintext blob under a
    session everything else considers converted — so what makes a profile stock is exactly what ``_stock_profiles``
    reports, and this repairs it either way.

    Mutates ``full_config`` alongside the file: both callers hand the same dict to whatever runs next. A failed
    conversion is also noted on it (see ``_note_reshape_failures``), because that same mutation is what makes the
    profile invisible to a later ``_stock_profiles`` scan — the note is the only record left of what happened.
    """
    converted: list[ProfileName] = []
    already: list[ProfileName] = []
    skeletons: list[ProfileName] = []
    failed: list[ProfileName] = []
    for profile, cfg in _session_profiles(session_name, full_config):
        account_id, role = cfg.get('sso_account_id'), cfg.get('sso_role_name')
        if not (account_id and role):
            # nothing to move into brolly_sso_*: already secure, or an incomplete profile only `switch` can finish
            (already if _is_secure(cfg) else skeletons).append(profile)
            continue
        secured = _secure_profile(profile, account_id, role, cfg.get('sso_account_name'), cfg)
        (converted if secured else failed).append(profile)
    _note_reshape_failures(full_config, session_name, failed)
    return _Reshaped(converted, already, skeletons, failed)


def heal_session_profiles(session_name: SessionName, full_config: AwsConfig) -> list[ProfileName]:
    """Convert any stock profile under an already-secured session, naming each one — never silent.

    A migration path, not steady-state: `secure enable` converts every profile up front, so a healthy session has
    none of these. They exist on upgrade from a brolly whose commands did not all dispatch on the session's mode,
    and while one survives it resolves credentials out of the plaintext blob and rotates a live refresh token back
    into it on every refresh. Healing is therefore what lets the purge that follows run unconditionally.
    """
    healed = _reshape_session_profiles(session_name, full_config).converted
    for profile in healed:
        print(
            f"✓ converted '{profile}' to secure mode — it was still resolving credentials from ~/.aws/sso/cache",
            file=sys.stderr,
        )
    return healed


def _registration_scopes(sso_config: AwsConfig) -> list[str]:
    """The scopes to register with: the sso-session's ``sso_registration_scopes``, always including _ACCOUNT_SCOPE."""
    configured = [s.strip() for s in sso_config.get('sso_registration_scopes', '').split(',') if s.strip()]
    return list(dict.fromkeys([_ACCOUNT_SCOPE, *configured]))


def _device_login(session_name: SessionName, sso_config: AwsConfig, cache: _KeychainTokenCache) -> None:
    """Run the sso-oidc device-authorization flow and store the resulting token blob (incl. refresh token) in keychain.

    botocore's token provider only *refreshes* an existing token; it never performs the initial device login, so
    brolly drives the OIDC dance itself. The blob's key set matches exactly what botocore's refresh path reads.

    It stores the token and deletes nothing. Clearing what the session left in ~/.aws/sso/cache belongs to the two
    places that heal the profiles first and hold the ``full_config`` the decision needs —
    ``cli._enter_secure_session`` and `secure enable` — and never to this, which runs before either has had its
    chance. See ``purge_session_plaintext`` for why a fresh keychain token is no licence to delete a stock
    profile's only credential.
    """
    start_url: str = sso_config['sso_start_url']
    sso_region: Region = sso_config['sso_region']
    oidc = boto3.client('sso-oidc', region_name=sso_region, config=Config(signature_version=UNSIGNED))
    registration = oidc.register_client(
        clientName=_CLIENT_NAME,
        clientType='public',
        scopes=_registration_scopes(sso_config),
        grantTypes=[_DEVICE_GRANT, _REFRESH_GRANT],
    )
    authorization = oidc.start_device_authorization(
        clientId=registration['clientId'], clientSecret=registration['clientSecret'], startUrl=start_url
    )
    print(
        f"\nTo authorize brolly for session '{session_name}', open:\n\n"
        f'    {authorization["verificationUriComplete"]}\n\n'
        f'and confirm the code: {authorization["userCode"]}\n',
        file=sys.stderr,
    )

    interval = authorization.get('interval', 5)
    while True:
        sleep(interval)
        try:
            token = oidc.create_token(
                clientId=registration['clientId'],
                clientSecret=registration['clientSecret'],
                grantType=_DEVICE_GRANT,
                deviceCode=authorization['deviceCode'],
            )
            break
        except oidc.exceptions.AuthorizationPendingException:
            continue
        except oidc.exceptions.SlowDownException:
            interval += 5
        except oidc.exceptions.ExpiredTokenException:
            raise SystemExit(
                'the authorization request expired before you approved it — run the command again'
            ) from None
        except oidc.exceptions.AccessDeniedException:
            raise SystemExit('authorization was denied') from None

    expires_at = datetime.now(UTC) + timedelta(seconds=token['expiresIn'])
    blob: TokenBlob = {
        'startUrl': start_url,
        'region': sso_region,
        'accessToken': token['accessToken'],
        'expiresAt': expires_at.isoformat(),
        'clientId': registration['clientId'],
        'clientSecret': registration['clientSecret'],
        'registrationExpiresAt': datetime.fromtimestamp(registration['clientSecretExpiresAt'], tz=UTC).isoformat(),
    }
    if 'refreshToken' in token:
        blob['refreshToken'] = token['refreshToken']
    cache[_cache_key(session_name)] = blob
    print('✓ authorized — SSO token stored in your OS keychain', file=sys.stderr)
    if 'refreshToken' not in blob:
        print(
            f'! IAM Identity Center issued no refresh token for this session, so it cannot renew silently — '
            f'expect another device login at {expires_at.astimezone():%Y-%m-%d %H:%M}.\n'
            f"  Check that the '{session_name}' sso-session is allowed the {_ACCOUNT_SCOPE} scope.",
            file=sys.stderr,
        )


def load_secure_token(
    profile: ProfileName, session_name: SessionName, keyring_module: ModuleType
) -> AccessToken | None:
    """A valid keychain-backed SSO access token for the profile (auto-refreshed); None if the session is dead."""
    session = botocore.session.Session(profile=profile)
    provider = SSOTokenProvider(session, cache=_KeychainTokenCache(keyring_module, session_name), profile_name=profile)
    token = provider.load_token()
    if token is None:
        return None
    try:
        frozen = token.get_frozen_token()
    except SSOTokenLoadError, TokenRetrievalError, UnauthorizedSSOTokenError:
        return None
    if frozen.expiration <= datetime.now(UTC):
        return None
    return frozen.token


def _ensure_secure_token(
    profile: ProfileName, session_name: SessionName, full_config: AwsConfig, keyring_module: ModuleType
) -> AccessToken:
    """The secure-mode counterpart of ``cli._ensure_token``: a live keychain token, device login only if needed."""
    token = load_secure_token(profile, session_name, keyring_module)
    if token is not None:
        return token
    print(f"SSO session '{session_name}' has no valid keychain token — logging in…", file=sys.stderr)
    cache = _KeychainTokenCache(keyring_module, session_name)
    _device_login(session_name, full_config['sso_sessions'][session_name], cache)
    token = load_secure_token(profile, session_name, keyring_module)
    if token is None:
        raise SystemExit('could not obtain a valid SSO token after login')
    return token


def cmd_credential_process(profile: ProfileName) -> None:
    """Machine-facing: emit the ``Version: 1`` credential JSON the AWS SDK/CLI expect for ``credential_process``."""
    session = botocore.session.Session(profile=profile)
    try:
        cfg = session.get_scoped_config()
    except ProfileNotFound:
        raise SystemExit(f"profile '{profile}' not found") from None
    session_name: SessionName | None = cfg.get('sso_session')
    account_id: AccountId | None = cfg.get('brolly_sso_account_id')
    role: RoleName | None = cfg.get('brolly_sso_role_name')
    if not (session_name and account_id and role):
        raise SystemExit(f"profile '{profile}' is not a brolly secure profile — run: brolly secure enable")
    full_config = session.full_config
    sso_sessions = full_config.get('sso_sessions', {})
    if session_name not in sso_sessions:
        raise SystemExit(f"sso-session '{session_name}' referenced by '{profile}' is not defined")
    sso_region: Region = sso_sessions[session_name]['sso_region']
    # Three lookups that miss on the common path (the files are normally absent), and all it prints goes to stderr —
    # stdout belongs to the credential JSON. Worth it: this runs on every cold resolution, so it is the path most
    # likely to be the first to notice a blob that some other tool wrote back into the cache. It reports and never
    # removes — the report-don't-mutate posture this already had toward ~/.aws/config, extended to the filesystem.
    report_session_plaintext(session_name, full_config)

    keyring_module = _configured_keyring()
    access_token = load_secure_token(profile, session_name, keyring_module)
    if access_token is None:
        raise SystemExit(f"no valid token for session '{session_name}' — run: brolly login -s {session_name}")

    sso = boto3.client('sso', region_name=sso_region, config=Config(signature_version=UNSIGNED))
    try:
        creds = sso.get_role_credentials(accountId=account_id, roleName=role, accessToken=access_token)[
            'roleCredentials'
        ]
    except sso.exceptions.UnauthorizedException:
        raise SystemExit(f"token rejected for session '{session_name}' — run: brolly login -s {session_name}") from None

    # The credential_process contract *is* to write the credentials as JSON on stdout, which the calling SDK
    # reads back over a pipe — this is the protocol's designed channel, not a log sink. Static analysis flags it
    # as clear-text logging of secrets (CodeQL py/clear-text-logging-sensitive-data); there is no alternative
    # that still implements credential_process. The credentials are short-lived STS session credentials.
    print(
        json.dumps({
            'Version': 1,
            'AccessKeyId': creds['accessKeyId'],
            'SecretAccessKey': creds['secretAccessKey'],
            'SessionToken': creds['sessionToken'],
            'Expiration': datetime.fromtimestamp(creds['expiration'] / 1000, tz=UTC).isoformat(),
        })
    )


def cmd_secure_enable(session_name: SessionName, full_config: AwsConfig, backend: str | None = None) -> None:
    """Log the session into the keychain and convert every profile under it to ``credential_process`` mode.

    Resolves the keyring backend (explicit ``--backend``, else the saved one, else auto-detect — a real OS keychain
    or a ready pass store) and **persists it** so later ``credential-process`` calls never touch the environment.

    It is persisted only once ``_prove_keychain`` has shown it actually works, which is why that proof is taken here
    rather than through ``preflight_keychain``: the backend being weighed is not yet the saved one. Saving first
    would mean a backend that loads and then refuses — a pass store gpg-agent will not unlock, a package that
    imports but cannot operate — is what ``_configured_keyring`` hands every later command, so one failed `enable`
    would drag already-working sessions down with it.
    """
    keyring_module = _import_keyring()
    backend = backend or _read_config().get('keyring_backend') or _autodetect_backend(keyring_module)
    if backend is None:
        raise SystemExit(_NO_KEYRING_BACKEND)
    _select_backend(keyring_module, backend)
    try:
        _prove_keychain(keyring_module, session_name)
    except SystemExit as x:
        raise SystemExit(
            f"{x}\n  keyring backend '{backend}' loaded but could not be used, so it was not saved and nothing "
            f'about this session was changed.'
        ) from None
    _write_config({**_read_config(), 'keyring_backend': backend})
    print(f'→ keychain backend: {_backend_label(keyring_module)}  (saved to {_config_path()})', file=sys.stderr)
    sso_config = full_config['sso_sessions'][session_name]
    cache = _KeychainTokenCache(keyring_module, session_name)
    try:
        stored: TokenBlob | None = cache[_cache_key(session_name)]
    except KeyError:
        stored = None
    if stored is None:
        _device_login(session_name, sso_config, cache)
    elif 'refreshToken' not in stored:
        # stored before brolly registered for the refresh_token grant — that token strands the session at the
        # access token's 8 hours, so re-authorize now rather than at its next expiry
        print(f"→ stored token for '{session_name}' cannot renew silently — re-authorizing", file=sys.stderr)
        _device_login(session_name, sso_config, cache)

    # Recorded before the profiles are touched: the session is secured the moment its token is in the keychain,
    # and a run that dies half-way through the rewrite below must still leave it detectable as such.
    _record_secured_session(session_name, True)

    # Heal first, purge second — `cli._enter_secure_session`'s order, for its reason: until the reshape has run,
    # a stock profile is still resolving its credentials out of the blob this would delete.
    reshaped = _reshape_session_profiles(session_name, full_config)
    purge_session_plaintext(session_name, full_config)
    converted, resolving = len(reshaped.converted), len(reshaped.converted) + len(reshaped.already)

    print(f"✓ secure mode on for session '{session_name}' — its token now lives in the OS keychain")
    if resolving:
        print(f'  {resolving} profile(s) resolve credentials through it ({converted} converted just now)')
    if reshaped.failed:
        print(
            f'  ! could not convert, so still resolving from ~/.aws/sso/cache: {", ".join(reshaped.failed)}\n'
            f'  fix the lines named above, then re-run — until then this session is only half in the keychain'
        )
    if reshaped.skeletons:
        print(
            f'  no account/role set yet, so left alone: {", ".join(reshaped.skeletons)}\n'
            f'  finish one with `AWS_PROFILE=<profile> brolly switch` — it will be written in secure shape'
        )
    elif not resolving:
        print(f'  it has no profiles yet — `brolly add <profile> -s {session_name}` creates one already secured')

    if reshaped.failed:
        # said in full above; the status is for whatever ran this — a half-enabled session still leaks a refresh
        # token through ~/.aws/sso/cache, and a script that cannot tell that from success will not come back
        raise SystemExit(1)


def _delete_keychain_token(session_name: SessionName) -> None:
    """Drop the session's keychain entry (and its sidecar), reporting rather than raising if the backend refuses.

    Only `secure disable` calls this, and by then every profile is already back to stock: an unreachable keychain
    must not turn a completed revert into a failed command. What it leaves behind is inert — nothing reads that
    entry once the session is no longer secured — so a named warning is the whole remedy.

    ``RuntimeError`` is caught alongside the ``SystemExit`` ``_keyring_call`` raises because resolving the backend
    is itself a keychain call, made before any ``_keyring_call`` wraps anything — see ``_keychain_failures`` for
    which backend raises what.
    """
    cache_key = _cache_key(session_name)
    try:
        cache = _KeychainTokenCache(_configured_keyring(), session_name)
        with suppress(KeyError):
            del cache[cache_key]
    except (SystemExit, RuntimeError) as x:
        print(
            f"! the OS keychain entry for session '{session_name}' could not be removed: {x}\n"
            f'  Nothing reads it now, but delete it yourself if you would rather it were gone.',
            file=sys.stderr,
        )
        _remove_sidecar(cache_key)


_SECURE_KEYS = {'credential_process', 'brolly_sso_account_id', 'brolly_sso_role_name'}

# What botocore has to read back before a profile counts as reverted: the pair its SSO credential provider
# activates on, and the session the token provider resolves that against. Two of the three without the third
# resolves nothing at all.
_STOCK_KEYS = ('sso_account_id', 'sso_role_name', 'sso_session')


def _revert_profile(profile: ProfileName, account_id: AccountId, role: RoleName) -> bool:
    """Write one secured profile back to stock shape, proving each half landed before the next is allowed to run.

    Returns whether botocore now reads this profile as a working stock SSO profile. The read-back is the same
    discipline ``_secure_profile`` applies in the other direction, and for the same reason — `aws configure set`
    matches section headers more strictly than botocore parses them, so an unusual header (``[profile  x]`` with
    two spaces, a quoted name, a trailing comment) makes it append a *second* section that shadows the first, and
    botocore then reads the profile as that section alone.

    What differs is the order: nothing is removed until the stock keys are proven present. A revert that lands in a
    shadowing section has already cost the profile its ``sso_session`` and its ``credential_process``; stripping
    the secure keys on top of that would leave nothing on disk to merge the two sections back from. So on a failed
    read-back the profile keeps every key it had, and the caller keeps the keychain token those keys resolve by.
    """
    _aws('configure', 'set', 'sso_account_id', account_id, '--profile', profile)
    _aws('configure', 'set', 'sso_role_name', role, '--profile', profile)
    if missing := [key for key in _STOCK_KEYS if not _profile_on_disk(profile).get(key)]:
        print(
            f"! '{profile}' is not back in stock shape after the revert — read back from {_aws_config_path()} it is "
            f'missing {", ".join(missing)}, so brolly removed none of its secure keys.\n'
            f'  `aws configure set` matches section headers more strictly than botocore reads them, so an unusual '
            f'header (a trailing comment, a quoted or oddly spaced name) makes it write a second [profile '
            f'{profile}] section that shadows the first — which is where the two lines it just wrote went. Merge '
            f'the two sections by hand, then re-run the command.',
            file=sys.stderr,
        )
        return False
    _config_remove_keys(profile, _SECURE_KEYS)
    if left := sorted(_SECURE_KEYS & _profile_on_disk(profile).keys()):
        print(
            f"! '{profile}' still carries {', '.join(left)} in {_aws_config_path()} after brolly tried to remove "
            f'them, so it is not back in stock shape — credential_process still points at a brolly that no longer '
            f'holds its token.\n'
            f'  Delete those lines from its section by hand, then re-run the command.',
            file=sys.stderr,
        )
        return False
    return True


def cmd_secure_disable(session_name: SessionName, full_config: AwsConfig) -> None:
    """Revert every secured profile under the session to a stock plaintext-cache SSO profile and purge the token.

    Ordered so it still works when the keychain does not. This is the documented way out of secure mode, and the
    reason to reach for it is often that the backend has become unusable — an uninstalled backend package, a
    gpg-agent that will not unlock — so the profile revert, which needs no keyring at all, runs first and the token
    deletion is a separate step allowed to fail. The record is dropped before that step for the same reason: a
    session whose profiles are back to stock while brolly still calls it secured would be silently re-secured by
    the next command.

    Both of those last two steps are conditional on every revert having landed, which is the one thing this command
    may not take on trust. A revert is a write to ~/.aws/config, and a write that misses its section (see
    ``_revert_profile``) leaves a profile resolving neither through the keychain nor through the plaintext cache —
    so deleting the token and dropping the record behind it would hand the user no credentials at all under a line
    saying secure mode was turned off. Profiles that did revert are left reverted, because re-securing them would
    be inventing a second failure; what a failure holds back is the keychain token, the record, and the ✓.

    Only the read-back moved into the revert loop, not the keychain: it is a file read, so an unreachable keychain
    still gets every profile it can back to stock before anything asks the keyring for anything.
    """
    reverted: list[ProfileName] = []
    failed: list[ProfileName] = []
    for profile, cfg in _session_profiles(session_name, full_config):
        if not _is_secure(cfg):
            continue
        # a conversion interrupted between its two `aws configure set` calls leaves no brolly role but its stock
        # keys still in place — reverting to those is exactly right, and beats a KeyError traceback
        account_id = cfg.get('brolly_sso_account_id') or cfg.get('sso_account_id')
        role = cfg.get('brolly_sso_role_name') or cfg.get('sso_role_name')
        if not (account_id and role):
            print(
                f"! '{profile}' has no role recorded under either brolly_sso_role_name or sso_role_name, so there "
                f'is nothing to revert it to — its brolly keys are removed, leaving it for '
                f'`AWS_PROFILE={profile} brolly switch` to finish.',
                file=sys.stderr,
            )
            # nothing this profile can resolve by is being taken away: it had no account/role either way, so it is
            # not a revert that failed and it does not hold the token back
            _config_remove_keys(profile, _SECURE_KEYS)
            continue
        (reverted if _revert_profile(profile, account_id, role) else failed).append(profile)

    if failed:
        print(
            f"! secure mode is still on for session '{session_name}' — {', '.join(failed)} could not be reverted, "
            f"so brolly kept its keychain token and the session's secured record rather than delete the credentials "
            f'a half-reverted profile is fixed back into.\n'
            f'  {len(reverted)} profile(s) did revert and read from the stock cache now'
            + (f': {", ".join(reverted)}' if reverted else '')
            + f'\n  Fix the profile(s) named above, then re-run:  brolly secure disable -s {session_name}'
        )
        raise SystemExit(1)

    _record_secured_session(session_name, False)
    _delete_keychain_token(session_name)
    print(f"✓ secure mode off for session '{session_name}' — {len(reverted)} profile(s) back to the stock cache")


def cmd_secure_login(session_name: SessionName, full_config: AwsConfig) -> None:
    """`brolly login` for a secured session: re-run the device login, refreshing the keychain token in place."""
    keyring_module = _configured_keyring()
    print(f'→ keychain backend: {_backend_label(keyring_module)}', file=sys.stderr)
    sso_config = full_config['sso_sessions'][session_name]
    cache = _KeychainTokenCache(keyring_module, session_name)
    _device_login(session_name, sso_config, cache)


def cmd_secure_switch(profile: ProfileName, full_config: AwsConfig) -> None:
    """Repoint a secured profile's account/role, keeping it in secure mode (writes ``brolly_sso_*``, not the cache)."""
    cfg = full_config['profiles'][profile]
    session_name: SessionName = cfg['sso_session']
    sso_region: Region = full_config['sso_sessions'][session_name]['sso_region']

    keyring_module = _configured_keyring()
    token = _ensure_secure_token(profile, session_name, full_config, keyring_module)
    account, role = _pick_account_role(
        sso_region, token, cfg.get('brolly_sso_account_id'), cfg.get('brolly_sso_role_name')
    )
    if not _secure_profile(profile, account['accountId'], role, account['accountName']):
        # `_secure_profile` has just printed why in full; what must not follow it is a ✓ line claiming a profile
        # was repointed when the write was refused — the caller would take that for a working secure profile
        raise SystemExit(1)
    print(f'✓  {profile} → {account["accountId"]} ({account["accountName"]}) / {role}')


def cmd_secure_add(session_name: SessionName, new_profile: ProfileName, full_config: AwsConfig) -> None:
    """`brolly add` for a secured session: create the profile already in secure shape.

    It never writes the standard ``sso_account_id``/``sso_role_name`` keys, not even briefly — they would activate
    botocore's SSO credential provider ahead of ``credential_process`` (see the module docstring).
    """
    sso_region = _create_profile_skeleton(session_name, new_profile, full_config)
    keyring_module = _configured_keyring()
    print(f'→ keychain backend: {_backend_label(keyring_module)}', file=sys.stderr)
    token = _ensure_secure_token(new_profile, session_name, full_config, keyring_module)
    purge_session_plaintext(session_name, full_config)
    account, role = _pick_account_role(sso_region, token)
    if not _secure_profile(new_profile, account['accountId'], role, account['accountName']):
        # `_secure_profile` has just printed why in full; what must not follow it is an "added" line claiming a
        # profile that is not in secure shape — the caller would take that for a working secure profile
        raise SystemExit(1)
    _report_added(new_profile, account, role)

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

# IAM Identity Center only returns a refresh token when the client registration asks for at least this scope, and
# only issues one at all when the registration declares the refresh_token grant. Without both, CreateToken hands
# back a bare 8-hour access token that botocore cannot renew — the session then dies at 8h no matter how long the
# access-portal session duration is set to. brolly needs this scope anyway to list accounts and roles.
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
    path = _sidecar_path(cache_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({'session': session_name, 'expiresAt': _iso(expires_at), 'refreshable': refreshable}))


def _remove_sidecar(cache_key: str) -> None:
    _sidecar_path(cache_key).unlink(missing_ok=True)


def _plaintext_token_path(session_name: SessionName) -> Path:
    """The stock plaintext SSO token file for a session — botocore's fixed ``~/.aws/sso/cache`` location."""
    return Path.home() / '.aws' / 'sso' / 'cache' / f'{_cache_key(session_name)}.json'


def _remove_plaintext_token(session_name: SessionName) -> bool:
    """Delete the now-redundant plaintext SSO token (it lives in the keychain now). True if a file was removed."""
    path = _plaintext_token_path(session_name)
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError as x:
        # a token we cannot delete must still not break the command that noticed it — report and carry on
        print(f'! could not remove the plaintext token cache {path}: {x}', file=sys.stderr)
        return False
    return True


def _purge_plaintext_token(session_name: SessionName) -> None:
    """Drop any plaintext blob for a secured session, saying so — silence would hide that a token was on disk.

    Unconditional, and only two callers may be: a completed device login and `secure enable`, both of which have
    just put a fresh token in the keychain — and enable converts every profile that was reading the file in the
    same run. Everything else goes through ``purge_session_plaintext``, which first checks nothing still needs it.
    """
    if _remove_plaintext_token(session_name):
        print(f"✓ removed plaintext token cache for session '{session_name}'", file=sys.stderr)


def _stock_profiles(session_name: SessionName, full_config: AwsConfig) -> list[ProfileName]:
    """Profiles under the session still carrying both stock SSO keys — botocore resolves those from the plaintext
    blob, and they are exactly the set ``_reshape_session_profiles`` converts, so what healing fixes is what this
    reports."""
    return sorted(
        p for p, c in _session_profiles(session_name, full_config) if c.get('sso_account_id') and c.get('sso_role_name')
    )


def purge_session_plaintext(session_name: SessionName, full_config: AwsConfig | None = None) -> None:
    """Clear a secured session's plaintext token whether or not this command authenticated — ``cli`` runs this from
    the one place that decides a session is secure, so no command can forget it.

    One guard, stated rather than silent: while a stock profile is still configured under the session, botocore
    resolves *its* credentials out of this very blob, and deleting it would break a working profile with nothing
    but a browser login to get it back. ``cli._enter_secure_session`` heals those profiles before it purges, so no
    user-facing command reaches this. It stands for ``cmd_credential_process``, which shares the purge but runs
    non-interactively on every cold credential resolution and must not rewrite ``~/.aws/config`` behind the SDK.
    """
    if not _plaintext_token_path(session_name).is_file():
        return  # the common case, and the only cost on it: one stat
    stock = _stock_profiles(session_name, full_config or botocore.session.Session().full_config)
    if stock:
        print(
            f"! session '{session_name}' is secured, but ~/.aws/sso/cache still holds its token — "
            f'{", ".join(stock)} still resolves credentials from it, so this command left it alone.\n'
            f'  Convert it and clear the file:  brolly secure enable -s {session_name}',
            file=sys.stderr,
        )
        return
    _purge_plaintext_token(session_name)


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
        """Run a keyring operation, turning any backend failure into a clean exit rather than a traceback."""
        try:
            return operation(*args)
        except self._keyring.errors.KeyringError as x:
            raise SystemExit(f'OS keychain access failed: {x}') from None

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

    def __delitem__(self, cache_key: str) -> None:
        try:
            self._keyring.delete_password(_KEYRING_SERVICE, cache_key)
        except self._keyring.errors.PasswordDeleteError:
            raise KeyError(cache_key) from None
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


def _secure_profile(
    profile: ProfileName,
    account_id: AccountId,
    role: RoleName,
    account_name: str | None,
    cfg: AwsConfig | None = None,
) -> bool:
    """Rewrite one profile into secure shape: add ``credential_process`` + ``brolly_sso_*``, drop the SSO trigger.

    Returns whether the profile really is secure now. The removal is a line edit against a file botocore parses
    more liberally than any matcher of ours, so the result is read back rather than assumed: a profile that kept
    its stock keys still resolves out of ~/.aws/sso/cache, and reporting it as converted would license deleting the
    very blob it reads.

    ``cfg`` is this profile's entry in a caller's already-loaded ``full_config``; passing it replaces that
    in-memory copy with what is now on disk, so nothing downstream in the same command works off a false premise.
    """
    command = f'brolly credential-process --profile {profile}'
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
    """One pass over a session's profiles: those rewritten into secure shape just now, those already in it, and
    those carrying no account/role to move."""

    converted: list[ProfileName]
    already: list[ProfileName]
    skeletons: list[ProfileName]


def _reshape_session_profiles(session_name: SessionName, full_config: AwsConfig) -> _Reshaped:
    """Rewrite every stock profile under the session into secure shape — the pass `secure enable` and healing share.

    Mutates ``full_config`` alongside the file: both callers hand the same dict to whatever runs next.
    """
    converted: list[ProfileName] = []
    already: list[ProfileName] = []
    skeletons: list[ProfileName] = []
    for profile, cfg in _session_profiles(session_name, full_config):
        if _is_secure(cfg):
            already.append(profile)
            continue
        account_id, role = cfg.get('sso_account_id'), cfg.get('sso_role_name')
        if not (account_id and role):
            skeletons.append(profile)  # an incomplete profile — nothing to move into brolly_sso_*
            continue
        _secure_profile(profile, account_id, role, cfg.get('sso_account_name'), cfg)
        converted.append(profile)
    return _Reshaped(converted, already, skeletons)


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
    _purge_plaintext_token(session_name)
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
    # One stat on the common path (the file is normally absent), and everything it may print goes to stderr —
    # stdout belongs to the credential JSON. Worth it: this runs on every cold resolution, so it is the path most
    # likely to be the first to notice a blob that some other tool wrote back into the cache.
    purge_session_plaintext(session_name, full_config)

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
    """
    keyring_module = _import_keyring()
    backend = backend or _read_config().get('keyring_backend') or _autodetect_backend(keyring_module)
    if backend is None:
        raise SystemExit(_NO_KEYRING_BACKEND)
    _select_backend(keyring_module, backend)
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

    # The token is safely in the keychain now — drop the redundant plaintext copy botocore/aws-cli left behind.
    # Unconditional here, unlike purge_session_plaintext: the reshape below converts every profile reading it.
    _purge_plaintext_token(session_name)

    reshaped = _reshape_session_profiles(session_name, full_config)
    converted, resolving = len(reshaped.converted), len(reshaped.converted) + len(reshaped.already)

    print(f"✓ secure mode on for session '{session_name}' — its token now lives in the OS keychain")
    if resolving:
        print(f'  {resolving} profile(s) resolve credentials through it ({converted} converted just now)')
    if reshaped.skeletons:
        print(
            f'  no account/role set yet, so left alone: {", ".join(reshaped.skeletons)}\n'
            f'  finish one with `AWS_PROFILE=<profile> brolly switch` — it will be written in secure shape'
        )
    elif not resolving:
        print(f'  it has no profiles yet — `brolly add <profile> -s {session_name}` creates one already secured')


def cmd_secure_disable(session_name: SessionName, full_config: AwsConfig) -> None:
    """Revert every secured profile under the session to a stock plaintext-cache SSO profile and purge the token."""
    keyring_module = _configured_keyring()
    reverted = 0
    for profile, cfg in _session_profiles(session_name, full_config):
        if not _is_secure(cfg):
            continue
        _aws('configure', 'set', 'sso_account_id', cfg['brolly_sso_account_id'], '--profile', profile)
        _aws('configure', 'set', 'sso_role_name', cfg['brolly_sso_role_name'], '--profile', profile)
        _config_remove_keys(profile, {'credential_process', 'brolly_sso_account_id', 'brolly_sso_role_name'})
        reverted += 1

    with suppress(KeyError):
        del _KeychainTokenCache(keyring_module, session_name)[_cache_key(session_name)]
    _record_secured_session(session_name, False)
    print(f"✓ secure mode off for session '{session_name}' — {reverted} profile(s) back to the stock cache")


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
    _secure_profile(profile, account['accountId'], role, account['accountName'])
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
    _secure_profile(new_profile, account['accountId'], role, account['accountName'])
    _report_added(new_profile, account, role)

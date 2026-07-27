"""Tests for brolly's opt-in OS-keychain secure mode.

Everything here runs offline: `keyring` and the boto3 sso/sso-oidc clients are faked, and the AWS config lives in
a tmp file via ``AWS_CONFIG_FILE``. No real keychain, no network, no credentials.
"""

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from hashlib import sha1
from types import ModuleType

import botocore.session
import pytest

from brolly import keychain


@pytest.fixture(autouse=True)
def _isolate_brolly_config(tmp_path, monkeypatch):
    """Keep every test off the real ~/.aws/brolly (config + sidecars) and off the real ~/.aws/sso/cache.

    HOME matters as well as AWS_CONFIG_FILE: the plaintext token path is botocore's fixed home-relative one, and
    the secure paths delete from it.
    """
    monkeypatch.setenv('AWS_CONFIG_FILE', str(tmp_path / 'config'))
    monkeypatch.setenv('HOME', str(tmp_path))


def _fake_module(**attributes: object) -> ModuleType:
    """A real module carrying just the attributes a keyring helper reads — the helpers are annotated ``ModuleType``,
    and a duck-typed class object standing in for one is a lie to the type checker as much as to the reader."""
    module = ModuleType('fake_keyring')
    for name, value in attributes.items():
        setattr(module, name, value)
    return module


class _FakeKeyring(ModuleType):
    """Minimal in-memory stand-in for the `keyring` module (service, username) -> secret string.

    A ``ModuleType`` subclass rather than a bare duck type, because every helper it is handed to is typed as taking
    the `keyring` module itself.
    """

    class errors:
        class KeyringError(Exception):
            pass

        class PasswordDeleteError(KeyringError):
            pass

    def __init__(self) -> None:
        super().__init__('fake_keyring')
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self._store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        try:
            del self._store[(service, username)]
        except KeyError:
            raise self.errors.PasswordDeleteError() from None


class _FakeOidc:
    class exceptions:
        class AuthorizationPendingException(Exception):
            pass

        class SlowDownException(Exception):
            pass

        class ExpiredTokenException(Exception):
            pass

        class AccessDeniedException(Exception):
            pass

    def __init__(self, pending_rounds: int = 1, with_refresh_token: bool = True) -> None:
        self._pending = pending_rounds
        self._with_refresh_token = with_refresh_token
        self.registration_kwargs: dict[str, object] = {}

    def register_client(self, **kwargs: object) -> dict[str, object]:
        self.registration_kwargs = kwargs
        return {
            'clientId': 'cid',
            'clientSecret': 'csecret',
            'clientSecretExpiresAt': int((datetime.now(UTC) + timedelta(days=90)).timestamp()),
        }

    def start_device_authorization(self, **_: object) -> dict[str, object]:
        return {
            'deviceCode': 'dc',
            'userCode': 'WXYZ-1234',
            'verificationUriComplete': 'https://device.sso/verify?code=WXYZ-1234',
            'interval': 1,
            'expiresIn': 600,
        }

    def create_token(self, **_: object) -> dict[str, object]:
        if self._pending > 0:
            self._pending -= 1
            raise self.exceptions.AuthorizationPendingException()
        token: dict[str, object] = {'accessToken': 'access-tok', 'expiresIn': 28800}
        if self._with_refresh_token:
            token['refreshToken'] = 'refresh-tok'
        return token


class _FakeSso:
    class exceptions:
        class UnauthorizedException(Exception):
            pass

    def __init__(self, expiration_ms: int) -> None:
        self._expiration_ms = expiration_ms
        self.seen_token: str | None = None

    def get_role_credentials(self, accountId: str, roleName: str, accessToken: str) -> dict[str, object]:
        self.seen_token = accessToken
        return {
            'roleCredentials': {
                'accessKeyId': 'AKIAEXAMPLE',
                'secretAccessKey': 'secret',
                'sessionToken': 'session',
                'expiration': self._expiration_ms,
            }
        }


_SESSION = 'corp'
_PROFILE = 'corp-prod'
_ACCOUNT = '222222222222'
_ROLE = 'AdministratorAccess'


def _write_config(path, *, secure: bool) -> None:
    lines = [
        '[sso-session corp]',
        'sso_start_url = https://corp.awsapps.com/start',
        'sso_region = us-east-1',
        '',
        '[profile corp-prod]',
        'sso_session = corp',
        'region = us-east-1',
    ]
    if secure:
        lines += [
            'brolly_sso_account_id = 222222222222',
            'brolly_sso_role_name = AdministratorAccess',
            'sso_account_name = corp-prod',
            'credential_process = brolly credential-process --profile corp-prod',
        ]
    else:
        lines += ['sso_account_id = 222222222222', 'sso_role_name = AdministratorAccess']
    path.write_text('\n'.join(lines) + '\n')


_STOCK = 'corp-legacy'
_SKELETON = 'corp-qa'


def _write_mixed_config(path, *, skeleton: bool = False) -> None:
    """A secured session with `corp-prod` already converted and `corp-legacy` still in stock shape — optionally
    plus a skeleton, the shape healing cannot finish."""
    lines = [
        '[sso-session corp]',
        'sso_start_url = https://corp.awsapps.com/start',
        'sso_region = us-east-1',
        '',
        '[profile corp-prod]',
        'sso_session = corp',
        'region = us-east-1',
        'brolly_sso_account_id = 222222222222',
        'brolly_sso_role_name = AdministratorAccess',
        'credential_process = brolly credential-process --profile corp-prod',
        '',
        f'[profile {_STOCK}]',
        'sso_session = corp',
        'region = us-east-1',
        'sso_account_id = 333333333333',
        'sso_role_name = ReadOnly',
        'sso_account_name = corp-legacy-acct',
    ]
    if skeleton:
        lines += ['', f'[profile {_SKELETON}]', 'sso_session = corp', 'region = us-east-1']
    path.write_text('\n'.join(lines) + '\n')


@pytest.fixture
def aws_env(tmp_path, monkeypatch):
    cfg = tmp_path / 'config'
    monkeypatch.setenv('AWS_CONFIG_FILE', str(cfg))
    monkeypatch.delenv('AWS_PROFILE', raising=False)
    return cfg


def _live_blob() -> dict[str, str]:
    return {'accessToken': 'access-tok', 'expiresAt': (datetime.now(UTC) + timedelta(days=1)).isoformat()}


def _stored_blob(keyring_module: _FakeKeyring, session_name: str = _SESSION) -> dict:
    """The blob the fake keychain holds for a session — asserted present before it is decoded, so a test that meant
    to check a stored token never passes by decoding a miss."""
    raw = keyring_module.get_password('brolly-sso', keychain._cache_key(session_name))
    assert raw is not None
    return json.loads(raw)


def _plant_plaintext_token(session_name: str = _SESSION, client_id: str | None = None):
    """A stale plaintext SSO blob at botocore's fixed cache path — HOME is tmp_path-isolated for every test here.

    ``client_id`` writes every key `aws sso login` really writes, including the registration the token was minted
    under ("Cache the registration alongside the token" — botocore/tokens.py). That copy is what lets a purge say
    which registration file in the directory is this session's — and the full key set is what makes a token blob a
    fair test of everything that must not mistake one for a registration: it carries clientId, clientSecret and
    expiresAt too, so only the accessToken tells them apart.
    """
    path = keychain._plaintext_token_path(session_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = {'accessToken': 'stale', 'refreshToken': 'leaked'}
    if client_id is not None:
        blob |= {
            'startUrl': 'https://corp.awsapps.com/start',
            'region': 'us-east-1',
            'expiresAt': (datetime.now(UTC) + timedelta(hours=8)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'clientId': client_id,
            'clientSecret': 'client-secret',
            'registrationExpiresAt': '2099-01-01T00:00:00Z',
        }
    path.write_text(json.dumps(blob))
    return path


def _aws_cli_registration_key(session_name: str = _SESSION, sso_config: dict | None = None) -> str:
    """The name the AWS CLI gives a session's client-registration blob, derived here rather than asked of brolly.

    Verbatim from awscli/botocore/utils.py, ``BaseSSOTokenFetcher._registration_cache_key``::

        args = {
            'tool': 'botocore',
            'startUrl': start_url,
            'region': self._sso_region,
            'scopes': scopes,
            'session_name': session_name,
        }
        return hashlib.sha1(json.dumps(args, sort_keys=True).encode('utf-8')).hexdigest()

    The whole point of that route is parity with somebody else's naming, so a test that called
    ``keychain._registration_cache_key`` for the expected name would only prove brolly agrees with itself.
    """
    config = sso_config if sso_config is not None else _SSO_CONFIG
    raw_scopes = config.get('sso_registration_scopes')
    args = {
        'tool': 'botocore',
        'startUrl': config['sso_start_url'],
        'region': config['sso_region'],
        'scopes': None if raw_scopes is None else [s.strip() for s in raw_scopes.split(',') if s.strip()],
        'session_name': session_name,
    }
    return sha1(json.dumps(args, sort_keys=True).encode('utf-8')).hexdigest()


_OTHER_SESSION = 'other-corp'
_UNRELATED_NAME = '0' * 40  # a cache-key-shaped name that is *not* the one the AWS CLI derives for this session


def _plant_registration(name: str, client_id: str, **extra: object):
    """A client-registration blob exactly as `aws sso login` writes one: a clientId, a client secret with a ~90-day
    life, an expiry — and nothing whatsoever naming the session, start URL or region it belongs to."""
    path = keychain._sso_cache_dir() / f'{name}.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    expires = (datetime.now(UTC) + timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ')
    path.write_text(
        json.dumps({'clientId': client_id, 'clientSecret': 'registration-secret', 'expiresAt': expires} | extra)
    )
    return path


def _secure_session_config() -> dict:
    """The in-memory config a purge sees under a healthy secured session: one converted profile holding nothing
    back, and the sso-session block the reproducible registration name is derived from."""
    return {
        'profiles': {_PROFILE: {'sso_session': _SESSION, 'brolly_sso_account_id': _ACCOUNT}},
        'sso_sessions': {_SESSION: _SSO_CONFIG},
    }


def _stub_keyring_backend(monkeypatch, keyring_module: _FakeKeyring) -> None:
    """Point `secure enable`'s backend resolution at a fake keychain, leaving the rest of the command real."""
    monkeypatch.setattr(keychain, '_import_keyring', lambda: keyring_module)
    monkeypatch.setattr(keychain, '_autodetect_backend', lambda _: 'fake.Backend')
    monkeypatch.setattr(keychain, '_select_backend', lambda *a: None)
    monkeypatch.setattr(keychain, '_backend_label', lambda _: 'fake')


def test_config_remove_keys_strips_only_named_keys_in_section(aws_env):
    _write_config(aws_env, secure=False)
    keychain._config_remove_keys(_PROFILE, {'sso_account_id', 'sso_role_name'})
    text = aws_env.read_text()
    assert 'sso_account_id' not in text
    assert 'sso_role_name' not in text
    assert 'sso_session = corp' in text  # untouched keys survive
    assert '[sso-session corp]' in text  # other sections untouched


def test_config_remove_keys_respects_section_boundaries(tmp_path, monkeypatch):
    cfg = tmp_path / 'config'
    cfg.write_text(
        '[profile a]\nsso_account_id = 111\n\n[profile b]\nsso_account_id = 222\n',
    )
    monkeypatch.setenv('AWS_CONFIG_FILE', str(cfg))
    keychain._config_remove_keys('a', {'sso_account_id'})
    text = cfg.read_text()
    assert 'sso_account_id = 111' not in text  # removed from a
    assert 'sso_account_id = 222' in text  # b's identical key preserved


_HEADER_FORMS = [
    pytest.param('[profile b] # trailing comment', 'b', id='trailing-comment'),
    pytest.param('[profile  b]', 'b', id='repeated-internal-whitespace'),
    pytest.param('[profile b ]', 'b', id='trailing-space'),
    pytest.param('[profile "my prof"]', 'my prof', id='quoted-name'),
    pytest.param('[default]', 'default', id='default'),
    pytest.param('[profilex b]', 'b', id='profile-prefixed-word'),
]


@pytest.mark.parametrize('header, profile', _HEADER_FORMS)
def test_config_remove_keys_strips_the_stock_keys_from_every_header_form_botocore_reads_as_the_profile(
    header, profile, aws_env
):
    """Header forms plain string equality against `[profile x]` used to miss — each of them a section botocore does
    read as this profile. A missed section is the whole blocker: the profile keeps sso_account_id/sso_role_name, so
    it goes on resolving out of ~/.aws/sso/cache while brolly reports it converted and deletes the blob.

    The expected profile name is not asserted from taste — it is read back out of botocore first, so this pins
    parity with the parser brolly has to agree with (including `[profilex b]`, which botocore's own
    ``key.startswith('profile')`` + shlex resolves to `b`).
    """
    aws_env.write_text(f'{header}\nsso_session = corp\nsso_account_id = 111111111111\nsso_role_name = ReadOnly\n')
    assert list(botocore.session.Session().full_config['profiles']) == [profile]  # botocore's reading, not ours

    keychain._config_remove_keys(profile, {'sso_account_id', 'sso_role_name'})

    assert botocore.session.Session(profile=profile).get_scoped_config() == {'sso_session': 'corp'}


_NEAR_MISS_HEADERS = [
    pytest.param('[profileb]', 'b', id='no-separator'),
    pytest.param('[sso-session b]', 'b', id='sso-session'),
    pytest.param('[profile b c]', 'b', id='three-words'),
    pytest.param('[ default ]', 'default', id='padded-default'),
]


@pytest.mark.parametrize('header, profile', _NEAR_MISS_HEADERS)
def test_config_remove_keys_leaves_a_section_botocore_does_not_read_as_the_profile_alone(header, profile, aws_env):
    """The other half of parity, and the reason the matcher cannot simply be loose: a header botocore does *not*
    resolve to this profile is somebody else's section, and deleting keys out of it edits config brolly was never
    asked to touch."""
    body = 'sso_session = corp\nsso_account_id = 111111111111\nsso_role_name = ReadOnly\n'
    aws_env.write_text(f'{header}\n{body}')
    assert profile not in botocore.session.Session().full_config['profiles']

    keychain._config_remove_keys(profile, {'sso_account_id', 'sso_role_name'})

    assert aws_env.read_text() == f'{header}\n{body}'


def test_config_remove_keys_matches_option_names_case_insensitively(aws_env):
    """configparser lowercases option names, so `SSO_Account_ID` is the same key to botocore — and still activates
    the SSO credential provider. Matching the file's casing left the trigger in place."""
    aws_env.write_text(
        f'[profile {_PROFILE}]\nsso_session = corp\nSSO_Account_ID = 111111111111\nSso_Role_Name = ReadOnly\n'
    )

    keychain._config_remove_keys(_PROFILE, {'sso_account_id', 'sso_role_name'})

    assert botocore.session.Session(profile=_PROFILE).get_scoped_config() == {'sso_session': 'corp'}


def test_config_remove_keys_removes_a_colon_delimited_option(aws_env):
    """configparser accepts `key: value` as readily as `key = value`, so a hand-written `sso_account_id: 123` is a
    live SSO trigger — splitting on `=` alone walked straight past it."""
    aws_env.write_text(
        f'[profile {_PROFILE}]\n'
        'sso_session = corp\n'
        'sso_account_id: 111111111111\n'
        'sso_role_name:ReadOnly\n'
        'sso_start_url = https://corp.awsapps.com/start\n'
    )

    keychain._config_remove_keys(_PROFILE, {'sso_account_id', 'sso_role_name'})

    cfg = botocore.session.Session(profile=_PROFILE).get_scoped_config()
    assert 'sso_account_id' not in cfg
    assert 'sso_role_name' not in cfg
    # a `=` line whose *value* holds a colon is still read on its first delimiter, so it is not taken for a key
    assert cfg['sso_start_url'] == 'https://corp.awsapps.com/start'


def test_config_remove_keys_leaves_every_other_byte_of_the_file_untouched(aws_env):
    """Why this is a line edit and not a configparser round-trip: deleting two keys must not cost the user their
    comments, blank lines, key ordering, indentation or casing anywhere else in ~/.aws/config."""
    aws_env.write_text(
        '# my aws config\n'
        '\n'
        '[sso-session corp]\n'
        'sso_start_url = https://corp.awsapps.com/start\n'
        'sso_region = us-east-1\n'
        '\n'
        f'[profile {_PROFILE}]   ; the one being converted\n'
        '  region = us-east-1\n'
        'sso_account_id = 111111111111\n'
        '# keep this comment\n'
        'sso_role_name = ReadOnly\n'
        'Output   =   JSON\n'
        '\n'
        '[profile other]\n'
        'sso_account_id = 999999999999\n'
    )

    keychain._config_remove_keys(_PROFILE, {'sso_account_id', 'sso_role_name'})

    assert aws_env.read_text() == (
        '# my aws config\n'
        '\n'
        '[sso-session corp]\n'
        'sso_start_url = https://corp.awsapps.com/start\n'
        'sso_region = us-east-1\n'
        '\n'
        f'[profile {_PROFILE}]   ; the one being converted\n'
        '  region = us-east-1\n'
        '# keep this comment\n'
        'Output   =   JSON\n'
        '\n'
        '[profile other]\n'
        'sso_account_id = 999999999999\n'
    )


def test_config_remove_keys_keeps_the_config_files_permissions(aws_env):
    """The rewrite goes through a temp file `mkstemp` creates at 0600, so without carrying the mode over brolly
    would silently re-permission a config the user (or their tooling) set deliberately."""
    _write_config(aws_env, secure=False)
    aws_env.chmod(0o640)

    keychain._config_remove_keys(_PROFILE, {'sso_account_id', 'sso_role_name'})

    assert stat.S_IMODE(aws_env.stat().st_mode) == 0o640


def test_cache_key_matches_botocore_convention():
    assert keychain._cache_key(_SESSION) == sha1(_SESSION.encode('utf-8')).hexdigest()


def test_backend_label_maps_known_and_unknown():
    def fake_get_keyring():
        cls = type('Keyring', (), {})
        cls.__module__ = 'keyring_pass'
        return cls()

    assert keychain._backend_label(_fake_module(get_keyring=fake_get_keyring)) == 'pass (gpg-agent)'

    def unknown_get_keyring():
        cls = type('WeirdBackend', (), {})
        cls.__module__ = 'some.other.vault'
        return cls()

    assert keychain._backend_label(_fake_module(get_keyring=unknown_get_keyring)) == 'some.other.vault.WeirdBackend'


def test_configured_keyring_reports_missing_backend(monkeypatch):
    import keyring
    import keyring.backends.fail

    monkeypatch.setattr(keyring, 'get_keyring', lambda: keyring.backends.fail.Keyring())
    with pytest.raises(SystemExit, match='no OS keychain backend'):
        keychain._configured_keyring()


def test_configured_keyring_applies_saved_backend(monkeypatch):
    keychain._write_config({'keyring_backend': 'some.pkg.Backend'})
    applied = []
    monkeypatch.setattr(keychain, '_import_keyring', _fake_module)
    monkeypatch.setattr(keychain, '_select_backend', lambda kr, name: applied.append(name))
    monkeypatch.setattr(keychain, '_is_fail_backend', lambda kr: False)
    keychain._configured_keyring()
    assert applied == ['some.pkg.Backend']


def test_config_roundtrip():
    assert keychain._read_config() == {}
    keychain._write_config({'keyring_backend': 'x.Y'})
    assert keychain._read_config() == {'keyring_backend': 'x.Y'}


def test_select_backend_missing_reports_cleanly():
    import keyring

    with pytest.raises(SystemExit, match='could not be loaded'):
        keychain._select_backend(keyring, 'nonexistent_pkg.NoBackend')


def test_pass_store_ready(tmp_path, monkeypatch):
    store = tmp_path / 'store'
    store.mkdir()
    monkeypatch.setenv('PASSWORD_STORE_DIR', str(store))
    monkeypatch.setattr(keychain.shutil, 'which', lambda name: '/usr/bin/pass')
    assert keychain._pass_store_ready() is False  # pass present but store not initialized
    (store / '.gpg-id').write_text('key-id\n')
    assert keychain._pass_store_ready() is True
    monkeypatch.setattr(keychain.shutil, 'which', lambda name: None)
    assert keychain._pass_store_ready() is False  # no pass binary


def test_autodetect_prefers_pass_when_no_os_keychain(monkeypatch):
    monkeypatch.setattr(keychain, '_is_fail_backend', lambda kr: True)
    monkeypatch.setattr(keychain, '_pass_store_ready', lambda: True)
    assert keychain._autodetect_backend(_fake_module()) == 'keyring_pass.PasswordStoreBackend'


def test_autodetect_returns_none_when_nothing_usable(monkeypatch):
    monkeypatch.setattr(keychain, '_is_fail_backend', lambda kr: True)
    monkeypatch.setattr(keychain, '_pass_store_ready', lambda: False)
    assert keychain._autodetect_backend(_fake_module()) is None


def test_autodetect_uses_active_os_keychain(monkeypatch):
    monkeypatch.setattr(keychain, '_is_fail_backend', lambda kr: False)
    backend = type('Keyring', (), {})
    backend.__module__ = 'keyring.backends.macOS'
    fake = _fake_module(get_keyring=lambda: backend())
    assert keychain._autodetect_backend(fake) == 'keyring.backends.macOS.Keyring'


def test_keychain_cache_translates_backend_failure(aws_env, monkeypatch):
    monkeypatch.setenv('AWS_CONFIG_FILE', str(aws_env))
    fake = _FakeKeyring()

    def boom(*_):
        raise fake.errors.KeyringError('keyring is locked')

    monkeypatch.setattr(fake, 'get_password', boom)
    cache = keychain._KeychainTokenCache(fake, _SESSION)
    with pytest.raises(SystemExit, match='OS keychain access failed'):
        _ = keychain._cache_key(_SESSION) in cache


def test_remove_plaintext_token(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    cache_dir = tmp_path / '.aws' / 'sso' / 'cache'
    cache_dir.mkdir(parents=True)
    token = cache_dir / f'{keychain._cache_key(_SESSION)}.json'
    token.write_text('{"accessToken": "plaintext-cruft", "refreshToken": "x"}')

    assert keychain._remove_plaintext_token(_SESSION) is True  # existed → removed
    assert not token.exists()
    assert keychain._remove_plaintext_token(_SESSION) is False  # already gone → nothing to do


def test_contains_suppresses_backend_stderr_noise(aws_env, capfd):
    class Noisy(_FakeKeyring):
        def get_password(self, service: str, username: str) -> str | None:
            os.write(2, b'Error: python-keyring/brolly-sso/abc is not in the password store.\n')
            return None

    cache = keychain._KeychainTokenCache(Noisy(), _SESSION)
    assert (keychain._cache_key(_SESSION) in cache) is False  # miss on a fresh session
    assert 'not in the password store' not in capfd.readouterr().err  # the pass noise is swallowed


def test_keychain_cache_roundtrip_and_sidecar(aws_env, monkeypatch):
    monkeypatch.setenv('AWS_CONFIG_FILE', str(aws_env))
    fake = _FakeKeyring()
    cache = keychain._KeychainTokenCache(fake, _SESSION)
    key = keychain._cache_key(_SESSION)
    expires = datetime.now(UTC) + timedelta(hours=8)

    assert key not in cache
    cache[key] = {'accessToken': 'tok', 'expiresAt': expires}  # datetime value must serialize
    assert key in cache
    assert cache[key]['accessToken'] == 'tok'

    sidecar = keychain._sidecar_path(key)
    assert sidecar.is_file()
    assert json.loads(sidecar.read_text()) == {
        'session': _SESSION,
        'expiresAt': expires.isoformat(),
        'refreshable': False,  # this blob carries no refresh token
    }

    del cache[key]
    assert key not in cache
    assert not sidecar.exists()

    with pytest.raises(KeyError):
        del cache[key]


def test_secure_profile_reshapes_config(aws_env):
    _write_config(aws_env, secure=False)
    keychain._secure_profile(_PROFILE, _ACCOUNT, _ROLE, 'corp-prod')
    cfg = botocore.session.Session(profile=_PROFILE).get_scoped_config()

    assert cfg['credential_process'] == f'brolly credential-process --profile {_PROFILE}'
    assert cfg['brolly_sso_account_id'] == _ACCOUNT
    assert cfg['brolly_sso_role_name'] == _ROLE
    assert cfg['sso_account_name'] == 'corp-prod'
    assert 'sso_account_id' not in cfg  # SSO credential-provider trigger removed
    assert 'sso_role_name' not in cfg
    assert cfg['sso_session'] == _SESSION  # token provider still needs it


def test_secured_profile_deactivates_sso_credential_provider(aws_env):
    """Load-bearing invariant: without account/role keys, botocore's SSO cred provider skips (falls to process)."""
    from botocore.credentials import ProfileProviderBuilder

    _write_config(aws_env, secure=True)
    builder = ProfileProviderBuilder(botocore.session.Session(profile=_PROFILE))
    assert builder._create_sso_provider(_PROFILE).load() is None


def test_heal_session_profiles_converts_a_stock_profile_and_names_it(aws_env, capsys):
    _write_mixed_config(aws_env)
    full_config = botocore.session.Session().full_config

    assert keychain.heal_session_profiles(_SESSION, full_config) == [_STOCK]

    cfg = botocore.session.Session(profile=_STOCK).get_scoped_config()
    assert cfg['brolly_sso_account_id'] == '333333333333'
    assert cfg['brolly_sso_role_name'] == 'ReadOnly'
    assert cfg['sso_account_name'] == 'corp-legacy-acct'  # preserved, so the prompt keeps its friendly name
    assert 'sso_account_id' not in cfg
    assert _STOCK in capsys.readouterr().err
    # the caller's in-memory config moved with the file — this is what lets the purge that follows run at all
    assert keychain._stock_profiles(_SESSION, full_config) == []


def test_heal_session_profiles_is_a_silent_noop_on_a_healthy_session(aws_env, capsys):
    _write_config(aws_env, secure=True)
    assert keychain.heal_session_profiles(_SESSION, botocore.session.Session().full_config) == []
    assert capsys.readouterr().err == ''


def test_heal_session_profiles_leaves_a_skeleton_alone(aws_env, capsys):
    _write_mixed_config(aws_env, skeleton=True)
    full_config = botocore.session.Session().full_config

    assert keychain.heal_session_profiles(_SESSION, full_config) == [_STOCK]

    assert botocore.session.Session(profile=_SKELETON).get_scoped_config() == {
        'sso_session': _SESSION,
        'region': 'us-east-1',
    }
    assert _SKELETON not in capsys.readouterr().err
    assert keychain._stock_profiles(_SESSION, full_config) == []  # a skeleton never held the blob back


_BOTH_SHAPES = 'corp-halfway'


def _write_both_shapes_config(path) -> None:
    """One profile carrying the stock pair *and* the brolly pair — an interrupted conversion, or a hand-edit. The
    stock pair is what botocore's SSO credential provider activates on, so it is still reading the plaintext blob
    however secure the rest of it looks."""
    path.write_text(
        '\n'.join([
            '[sso-session corp]',
            'sso_start_url = https://corp.awsapps.com/start',
            'sso_region = us-east-1',
            '',
            f'[profile {_BOTH_SHAPES}]',
            'sso_session = corp',
            'region = us-east-1',
            'sso_account_id = 333333333333',
            'sso_role_name = ReadOnly',
            'brolly_sso_account_id = 222222222222',
            'brolly_sso_role_name = AdministratorAccess',
            f'credential_process = brolly credential-process --profile {_BOTH_SHAPES}',
        ])
        + '\n'
    )


def _write_shadowed_header_config(path) -> None:
    """A one-profile session whose only profile sits under a header `aws configure set` will not recognize as the
    existing section (two spaces where botocore's shlex-based parser sees only one). `aws configure set` then
    appends a *second*, plain `[profile corp-prod]` section, and botocore resolves the profile entirely out of
    that last section — dropping sso_session and the stock keys from view along with it. Nothing here is mocked:
    this is the realistic shape that defeats `_config_remove_keys` on its own, without any monkeypatching."""
    path.write_text(
        '\n'.join([
            '[sso-session corp]',
            'sso_start_url = https://corp.awsapps.com/start',
            'sso_region = us-east-1',
            '',
            f'[profile  {_PROFILE}]',  # two spaces: still this profile to botocore, not to `aws configure set`
            'sso_session = corp',
            'region = us-east-1',
            f'sso_account_id = {_ACCOUNT}',
            f'sso_role_name = {_ROLE}',
        ])
        + '\n'
    )


def test_reshape_converts_a_profile_that_carries_both_shapes_at_once(aws_env):
    """Keyed on the stock pair, never on the absence of brolly_sso_*: this profile reads as secure and *is* still
    resolving out of ~/.aws/sso/cache. Bucketing it as `already` left that leak open under a session everything
    else considered converted — and told the purge there was nothing holding the blob back."""
    _write_both_shapes_config(aws_env)
    full_config = botocore.session.Session().full_config

    reshaped = keychain._reshape_session_profiles(_SESSION, full_config)

    assert reshaped == keychain._Reshaped(converted=[_BOTH_SHAPES], already=[], skeletons=[], failed=[])
    cfg = botocore.session.Session(profile=_BOTH_SHAPES).get_scoped_config()
    assert 'sso_account_id' not in cfg
    assert 'sso_role_name' not in cfg
    assert cfg['brolly_sso_account_id'] == '333333333333'  # the live pair moved, not the stale brolly one
    assert cfg['brolly_sso_role_name'] == 'ReadOnly'
    # the complementarity that licenses the purge: what makes a profile stock is exactly what this repaired
    assert keychain._stock_profiles(_SESSION, full_config) == []


def test_healing_a_both_shapes_profile_releases_the_plaintext_blob(aws_env, monkeypatch, capsys):
    """The same case end to end: the blob stays on disk until nothing resolves out of it, and a both-shapes profile
    did — so healing has to convert it before the purge is legitimately unblocked."""
    _write_both_shapes_config(aws_env)
    plaintext = _plant_plaintext_token()
    full_config = botocore.session.Session().full_config

    assert keychain.heal_session_profiles(_SESSION, full_config) == [_BOTH_SHAPES]
    keychain.purge_session_plaintext(_SESSION, full_config)

    assert not plaintext.exists()
    assert _BOTH_SHAPES in capsys.readouterr().err  # never silent about a profile it rewrote unasked


def test_entering_a_secured_session_leaves_the_plaintext_blob_when_healing_cannot_convert_a_profile(aws_env, capsys):
    """The hole this closes, reached exactly the way `cli._enter_secure_session` reaches it: heal, then purge.
    A shadowed-section profile fails the conversion `heal_session_profiles` attempts, and the very failure that
    ``_secure_profile`` reads back replaces the caller's in-memory copy of the profile with a reading that no
    longer even carries ``sso_session`` — invisible to ``_stock_profiles``, and so unable to hold the purge back
    by itself. Nothing here is mocked: the bad header alone defeats ``_config_remove_keys``."""
    _write_shadowed_header_config(aws_env)
    plaintext = _plant_plaintext_token()
    stale_bytes = plaintext.read_bytes()
    full_config = botocore.session.Session().full_config

    assert keychain.heal_session_profiles(_SESSION, full_config) == []  # nothing converted — it failed
    assert keychain._stock_profiles(_SESSION, full_config) == []  # and the failure made it invisible here too

    keychain.purge_session_plaintext(_SESSION, full_config)

    assert plaintext.read_bytes() == stale_bytes  # left alone, byte for byte
    err = capsys.readouterr().err
    assert _PROFILE in err
    assert 'deliberately left' in err


def test_reshape_separates_a_skeleton_from_an_already_secure_profile(aws_env):
    """The two shapes with no account/role to move look alike to the loop and must not be reported alike: one is
    finished, the other is waiting on `brolly switch`."""
    _write_mixed_config(aws_env, skeleton=True)
    full_config = botocore.session.Session().full_config

    reshaped = keychain._reshape_session_profiles(_SESSION, full_config)

    assert reshaped == keychain._Reshaped(converted=[_STOCK], already=[_PROFILE], skeletons=[_SKELETON], failed=[])
    assert botocore.session.Session(profile=_SKELETON).get_scoped_config() == {
        'sso_session': _SESSION,
        'region': 'us-east-1',
    }


def test_secure_profile_refuses_to_call_a_profile_converted_while_its_stock_keys_survive(aws_env, monkeypatch, capsys):
    """The blocker itself: the removal is a line edit against a file botocore parses more liberally than any matcher
    of ours, so its result is read back rather than assumed. A profile whose stock keys survived still resolves out
    of ~/.aws/sso/cache, and calling it converted is what licenses deleting the very blob it reads."""
    _write_config(aws_env, secure=False)
    monkeypatch.setattr(keychain, '_config_remove_keys', lambda *a, **k: None)  # a removal that does not land
    cfg = botocore.session.Session().full_config['profiles'][_PROFILE]

    assert keychain._secure_profile(_PROFILE, _ACCOUNT, _ROLE, 'corp-prod', cfg) is False

    err = capsys.readouterr().err
    assert _PROFILE in err
    assert str(aws_env) in err  # names the file the user has to edit by hand
    on_disk = botocore.session.Session(profile=_PROFILE).get_scoped_config()
    assert on_disk['sso_account_id'] == _ACCOUNT  # the disk truth, unchanged
    assert cfg == on_disk  # and the caller's in-memory copy was replaced by it, not by the hoped-for shape


def test_secure_profile_reports_the_second_section_an_unusual_header_makes_aws_configure_set_write(aws_env, capsys):
    """The read-back's other job, with nothing mocked: `aws configure set` matches section headers far more strictly
    than botocore reads them, so under `[profile  corp-prod]` (two spaces) it appends a *fresh* `[profile
    corp-prod]` — and botocore then resolves the profile entirely out of that last section, losing sso_session with
    it. Assuming the rewrite landed would report a profile as secured that can no longer resolve anything at all."""
    aws_env.write_text(
        '\n'.join([
            '[sso-session corp]',
            'sso_start_url = https://corp.awsapps.com/start',
            'sso_region = us-east-1',
            '',
            f'[profile  {_PROFILE}]',  # two spaces: still this profile to botocore, not to `aws configure set`
            'sso_session = corp',
            'region = us-east-1',
            f'sso_account_id = {_ACCOUNT}',
            f'sso_role_name = {_ROLE}',
        ])
        + '\n'
    )

    assert keychain._secure_profile(_PROFILE, _ACCOUNT, _ROLE, None) is False

    err = capsys.readouterr().err
    assert _PROFILE in err
    assert 'missing sso_session' in err
    assert 'second [profile corp-prod] section' in err  # names what happened, not just that something did


def test_secure_enable_heals_a_stock_profile_before_it_purges_the_plaintext_blob(aws_env, monkeypatch, capsys):
    """Order, asserted on the end state: while a stock profile is under the session, the blob is what resolves its
    credentials, so `enable` converts it first and only then deletes the file."""
    _write_mixed_config(aws_env)
    plaintext = _plant_plaintext_token()
    fake_keyring = _FakeKeyring()
    fake_keyring.set_password(
        'brolly-sso', keychain._cache_key(_SESSION), json.dumps({**_live_blob(), 'refreshToken': 'good'})
    )
    _stub_keyring_backend(monkeypatch, fake_keyring)

    keychain.cmd_secure_enable(_SESSION, botocore.session.Session().full_config)

    cfg = botocore.session.Session(profile=_STOCK).get_scoped_config()
    assert cfg['brolly_sso_account_id'] == '333333333333'
    assert 'sso_account_id' not in cfg
    assert not plaintext.exists()  # healing removed the last reader, so the purge had nothing to hold it back


def test_secure_enable_keeps_the_plaintext_blob_when_a_profile_could_not_be_converted(aws_env, monkeypatch, capsys):
    """The inverse of the ordering, and the reason `enable` no longer purges unconditionally: a profile whose stock
    keys survived is still resolving out of this file, so deleting it would break a working profile with nothing
    but a browser login to get it back."""
    _write_mixed_config(aws_env)
    plaintext = _plant_plaintext_token()
    fake_keyring = _FakeKeyring()
    fake_keyring.set_password(
        'brolly-sso', keychain._cache_key(_SESSION), json.dumps({**_live_blob(), 'refreshToken': 'good'})
    )
    _stub_keyring_backend(monkeypatch, fake_keyring)
    monkeypatch.setattr(keychain, '_config_remove_keys', lambda *a, **k: None)  # a removal that does not land

    with pytest.raises(SystemExit):
        keychain.cmd_secure_enable(_SESSION, botocore.session.Session().full_config)

    assert plaintext.read_text() == '{"accessToken": "stale", "refreshToken": "leaked"}'  # untouched
    captured = capsys.readouterr()
    assert f'could not convert, so still resolving from ~/.aws/sso/cache: {_STOCK}' in captured.out
    assert 'sso_account_id' in botocore.session.Session(profile=_STOCK).get_scoped_config()  # and it says so truly


def test_secure_enable_exits_non_zero_after_reporting_a_profile_it_could_not_convert(aws_env, monkeypatch, capsys):
    """A partial enable leaves a profile rotating a live refresh token through ~/.aws/sso/cache. The summary is
    printed in full first — the status is for whatever ran the command, which cannot read prose."""
    _write_mixed_config(aws_env, skeleton=True)
    fake_keyring = _FakeKeyring()
    fake_keyring.set_password(
        'brolly-sso', keychain._cache_key(_SESSION), json.dumps({**_live_blob(), 'refreshToken': 'good'})
    )
    _stub_keyring_backend(monkeypatch, fake_keyring)
    monkeypatch.setattr(keychain, '_config_remove_keys', lambda *a, **k: None)

    with pytest.raises(SystemExit) as exc_info:
        keychain.cmd_secure_enable(_SESSION, botocore.session.Session().full_config)

    assert exc_info.value.code == 1
    out = capsys.readouterr().out
    assert f"secure mode on for session '{_SESSION}'" in out
    assert f'could not convert, so still resolving from ~/.aws/sso/cache: {_STOCK}' in out
    assert f'no account/role set yet, so left alone: {_SKELETON}' in out  # the whole summary, not a truncated one


def test_secure_enable_leaves_the_plaintext_blob_untouched_when_a_shadowed_header_defeats_the_conversion(
    aws_env, monkeypatch, capsys
):
    """The hole this closes: `_stock_profiles` alone cannot hold the purge back here, because the very failure that
    ``_secure_profile`` reads back off disk replaces the profile's in-memory entry with a reading that has lost
    ``sso_session`` along with the stock keys — invisible to a later scan, not just unconverted. `secure enable`
    must not treat the absence of a `_stock_profiles` hit as license to purge. Nothing is mocked: the shadowed
    header alone defeats ``_config_remove_keys``, the realistic path rather than a stubbed-out one."""
    _write_shadowed_header_config(aws_env)
    plaintext = _plant_plaintext_token()
    stale_bytes = plaintext.read_bytes()
    fake_keyring = _FakeKeyring()
    fake_keyring.set_password(
        'brolly-sso', keychain._cache_key(_SESSION), json.dumps({**_live_blob(), 'refreshToken': 'good'})
    )
    _stub_keyring_backend(monkeypatch, fake_keyring)

    with pytest.raises(SystemExit) as exc_info:
        keychain.cmd_secure_enable(_SESSION, botocore.session.Session().full_config)

    assert exc_info.value.code == 1
    assert plaintext.read_bytes() == stale_bytes  # left alone, byte for byte — not merely "still present"
    err = capsys.readouterr().err
    assert _PROFILE in err
    assert 'deliberately left' in err


_FOREIGN = 'corp-foreign'
_FOREIGN_PROCESS = '/opt/acme/aws-credentials.sh --role reader'


def _write_foreign_credential_process_config(path) -> None:
    """A secured session with two stock profiles: `corp-legacy` clean, `corp-foreign` already carrying a credential
    helper of the user's own. Converting the one and refusing the other is the whole of the case."""
    path.write_text(
        '\n'.join([
            '[sso-session corp]',
            'sso_start_url = https://corp.awsapps.com/start',
            'sso_region = us-east-1',
            '',
            f'[profile {_STOCK}]',
            'sso_session = corp',
            'sso_account_id = 333333333333',
            'sso_role_name = ReadOnly',
            '',
            f'[profile {_FOREIGN}]',
            'sso_session = corp',
            'sso_account_id = 444444444444',
            'sso_role_name = ReadOnly',
            f'credential_process = {_FOREIGN_PROCESS}',
        ])
        + '\n'
    )


def test_secure_enable_refuses_to_overwrite_a_credential_process_brolly_did_not_write(aws_env, monkeypatch, capsys):
    """Secure mode needs ``credential_process`` for itself, but a user's own credential helper is not brolly's to
    destroy — and it used to be overwritten silently, with nothing left on disk to restore it from. A foreign value
    is a conflict: the profile is left exactly as it is, named with its command, and the session's plaintext token
    stays put because a profile that did not convert is still resolving out of it. The pass goes on: the other
    stock profile under the session is converted in the same run."""
    _write_foreign_credential_process_config(aws_env)
    plaintext = _plant_plaintext_token()
    stale_bytes = plaintext.read_bytes()
    fake_keyring = _FakeKeyring()
    fake_keyring.set_password(
        'brolly-sso', keychain._cache_key(_SESSION), json.dumps({**_live_blob(), 'refreshToken': 'good'})
    )
    _stub_keyring_backend(monkeypatch, fake_keyring)

    with pytest.raises(SystemExit) as exc_info:
        keychain.cmd_secure_enable(_SESSION, botocore.session.Session().full_config)

    assert exc_info.value.code == 1
    foreign = botocore.session.Session(profile=_FOREIGN).get_scoped_config()
    assert foreign['credential_process'] == _FOREIGN_PROCESS  # untouched, and still the profile's own helper
    assert foreign['sso_account_id'] == '444444444444'  # not converted: nothing was written at all
    assert 'brolly_sso_account_id' not in foreign
    converted = botocore.session.Session(profile=_STOCK).get_scoped_config()
    assert converted['brolly_sso_account_id'] == '333333333333'  # the run continued past the conflict
    assert converted['credential_process'] == f'brolly credential-process --profile {_STOCK}'
    assert plaintext.read_bytes() == stale_bytes  # a profile that did not convert holds the purge back
    captured = capsys.readouterr()
    assert _FOREIGN in captured.err
    assert _FOREIGN_PROCESS in captured.err  # names the value, so the user can see what would have been destroyed
    assert f'could not convert, so still resolving from ~/.aws/sso/cache: {_FOREIGN}' in captured.out


def test_secure_profile_treats_brollys_own_credential_process_as_ours_and_not_a_conflict(aws_env, capsys):
    """The other half of the rule, and the one that keeps every secure command idempotent: what a converted profile
    carries is brolly's own ``credential-process`` line, so re-running over it must convert, not conflict."""
    _write_config(aws_env, secure=True)
    aws_env.write_text(aws_env.read_text() + 'sso_account_id = 555555555555\nsso_role_name = ReadOnly\n')

    assert keychain._secure_profile(_PROFILE, '555555555555', 'ReadOnly', None) is True

    cfg = botocore.session.Session(profile=_PROFILE).get_scoped_config()
    assert cfg['credential_process'] == f'brolly credential-process --profile {_PROFILE}'
    assert cfg['brolly_sso_account_id'] == '555555555555'
    assert 'conflict' not in capsys.readouterr().err


def test_secure_switch_fails_loudly_rather_than_claiming_a_profile_it_could_not_write(aws_env, monkeypatch, capsys):
    """`switch` ends in a ✓ line naming an account and role. When ``_secure_profile`` refuses the write — here on a
    hand-edited profile whose credential_process is somebody else's — that line would be a claim about a profile
    that was never touched, and whatever ran the command would take it for a working secure profile."""
    aws_env.write_text(
        '\n'.join([
            '[sso-session corp]',
            'sso_start_url = https://corp.awsapps.com/start',
            'sso_region = us-east-1',
            '',
            f'[profile {_PROFILE}]',
            'sso_session = corp',
            'brolly_sso_account_id = 222222222222',
            'brolly_sso_role_name = AdministratorAccess',
            f'credential_process = {_FOREIGN_PROCESS}',
        ])
        + '\n'
    )
    fake_keyring = _FakeKeyring()
    fake_keyring.set_password('brolly-sso', keychain._cache_key(_SESSION), json.dumps(_live_blob()))
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: fake_keyring)
    monkeypatch.setattr(keychain, '_pick_account_role', lambda *a, **k: ({'accountId': '999', 'accountName': 'x'}, 'R'))

    with pytest.raises(SystemExit) as exc_info:
        keychain.cmd_secure_switch(_PROFILE, botocore.session.Session().full_config)

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert f'{_PROFILE} → ' not in captured.out  # no ✓ line for a write that was refused
    assert _FOREIGN_PROCESS in captured.err
    assert botocore.session.Session(profile=_PROFILE).get_scoped_config()['credential_process'] == _FOREIGN_PROCESS


def test_secure_add_fails_loudly_rather_than_claiming_a_profile_it_could_not_write(aws_env, monkeypatch, capsys):
    """`add`'s twin of the same false success. It ends in an "added" line naming an account and role, and when
    ``_secure_profile`` refuses the write that line describes a profile which resolves credentials from nowhere:
    no ``credential_process``, no ``brolly_sso_*``, and under a secured session no plaintext token either.

    Why the refusal is stubbed rather than staged: what makes ``_secure_profile`` say no — a foreign
    ``credential_process``, a rewrite it reads back as not having landed — has its own tests either side of this
    one. The bug here was never in the answer; it was that `add` did not look at it."""
    _write_config(aws_env, secure=True)  # corp-prod already secure; corp-dev is the new profile
    fake_keyring = _FakeKeyring()
    fake_keyring.set_password('brolly-sso', keychain._cache_key(_SESSION), json.dumps(_live_blob()))
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: fake_keyring)
    monkeypatch.setattr(keychain, '_backend_label', lambda _: 'fake')
    new_account = {'accountId': '333333333333', 'accountName': 'corp-dev'}
    monkeypatch.setattr(keychain, '_pick_account_role', lambda *a, **k: (new_account, 'ReadOnly'))
    monkeypatch.setattr(keychain, '_secure_profile', lambda *a, **k: False)

    with pytest.raises(SystemExit) as exc_info:
        keychain.cmd_secure_add(_SESSION, 'corp-dev', botocore.session.Session().full_config)

    assert exc_info.value.code == 1
    assert 'added corp-dev' not in capsys.readouterr().out  # no ✓ line for a profile that was never written


_CREDENTIAL_PROCESS_FORMS = [
    pytest.param('brolly credential-process --profile corp-prod', True, id='what-brolly-writes'),
    pytest.param('/usr/local/bin/brolly credential-process --profile corp-prod', True, id='absolute-path'),
    pytest.param('uv run brolly credential-process --profile corp-prod', True, id='through-a-runner'),
    pytest.param('brolly credential-process --profile someone-else', True, id='brollys-own-wrong-profile'),
    pytest.param('/opt/acme/aws-credentials.sh --role reader', False, id='another-tools-helper'),
    pytest.param('aws configure export-credentials --profile corp-prod', False, id='the-aws-cli'),
    pytest.param('brolly-wrapper credential-process', False, id='name-that-merely-starts-with-brolly'),
    pytest.param('sh -c "unbalanced', False, id='unparseable'),
]


@pytest.mark.parametrize('command, ours', _CREDENTIAL_PROCESS_FORMS)
def test_brolly_recognizes_its_own_credential_process_however_it_is_spelled(command, ours):
    """Where the line between idempotent and conflict actually falls. Too strict and brolly declares a conflict
    over its own helper spelled with a path; too loose and it overwrites somebody else's."""
    assert keychain._is_brolly_credential_process(command) is ours


def test_secure_enable_and_healing_share_one_pass_over_the_profiles(aws_env, monkeypatch, capsys):
    """`secure enable` converts up front what healing converts on upgrade — one helper, so they cannot disagree."""
    _write_mixed_config(aws_env, skeleton=True)
    fake_keyring = _FakeKeyring()
    fake_keyring.set_password(
        'brolly-sso', keychain._cache_key(_SESSION), json.dumps({**_live_blob(), 'refreshToken': 'good'})
    )
    monkeypatch.setattr(keychain, '_import_keyring', lambda: fake_keyring)
    monkeypatch.setattr(keychain, '_autodetect_backend', lambda _: 'fake.Backend')
    monkeypatch.setattr(keychain, '_select_backend', lambda *a: None)
    monkeypatch.setattr(keychain, '_backend_label', lambda _: 'fake')

    keychain.cmd_secure_enable(_SESSION, botocore.session.Session().full_config)

    out = capsys.readouterr().out
    assert '2 profile(s) resolve credentials through it (1 converted just now)' in out
    assert f'no account/role set yet, so left alone: {_SKELETON}' in out
    assert 'brolly_sso_account_id' in botocore.session.Session(profile=_STOCK).get_scoped_config()


def test_credential_process_emits_version_1_json(aws_env, monkeypatch, capsys):
    _write_config(aws_env, secure=True)
    fake_keyring = _FakeKeyring()
    fake_keyring.set_password('brolly-sso', keychain._cache_key(_SESSION), json.dumps(_live_blob()))
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: fake_keyring)

    expiration_ms = int((datetime.now(UTC) + timedelta(hours=1)).timestamp() * 1000)
    fake_sso = _FakeSso(expiration_ms)
    monkeypatch.setattr(keychain.boto3, 'client', lambda *a, **k: fake_sso)

    keychain.cmd_credential_process(_PROFILE)
    out = json.loads(capsys.readouterr().out)

    assert out['Version'] == 1
    assert out['AccessKeyId'] == 'AKIAEXAMPLE'
    assert out['SecretAccessKey'] == 'secret'
    assert out['SessionToken'] == 'session'
    assert out['Expiration'] == datetime.fromtimestamp(expiration_ms / 1000, tz=UTC).isoformat()
    assert fake_sso.seen_token == 'access-tok'  # token pulled from the keychain blob


def test_credential_process_rejects_non_secure_profile(aws_env):
    _write_config(aws_env, secure=False)  # standard SSO profile, no brolly_sso_* keys
    with pytest.raises(SystemExit, match='not a brolly secure profile'):
        keychain.cmd_credential_process(_PROFILE)


def test_credential_process_reports_unknown_profile(aws_env):
    _write_config(aws_env, secure=True)
    with pytest.raises(SystemExit, match="profile 'ghost' not found"):
        keychain.cmd_credential_process('ghost')


def test_credential_process_reports_dead_token(aws_env, monkeypatch):
    _write_config(aws_env, secure=True)
    fake_keyring = _FakeKeyring()  # empty: no token stored
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: fake_keyring)
    with pytest.raises(SystemExit, match='brolly login'):
        keychain.cmd_credential_process(_PROFILE)


_SSO_CONFIG = {'sso_start_url': 'https://corp.awsapps.com/start', 'sso_region': 'us-east-1'}


def _login(monkeypatch, keyring_module, *, oidc: _FakeOidc, sso_config: dict | None = None) -> None:
    monkeypatch.setattr(keychain, 'sleep', lambda _: None)
    monkeypatch.setattr(keychain.boto3, 'client', lambda *a, **k: oidc)
    cache = keychain._KeychainTokenCache(keyring_module, _SESSION)
    keychain._device_login(_SESSION, sso_config or _SSO_CONFIG, cache)


def test_device_login_stores_blob_and_sidecar(aws_env, monkeypatch):
    monkeypatch.setenv('AWS_CONFIG_FILE', str(aws_env))
    fake_keyring = _FakeKeyring()
    _login(monkeypatch, fake_keyring, oidc=_FakeOidc(pending_rounds=2))  # exercise the polling loop

    blob = _stored_blob(fake_keyring)
    assert blob['accessToken'] == 'access-tok'
    assert blob['refreshToken'] == 'refresh-tok'  # needed for silent refresh later
    assert blob['clientId'] == 'cid'
    assert blob['clientSecret'] == 'csecret'
    assert 'registrationExpiresAt' in blob
    sidecar = keychain._sidecar_path(keychain._cache_key(_SESSION))
    assert sidecar.is_file()
    assert json.loads(sidecar.read_text())['refreshable'] is True


def test_device_login_registers_for_the_refresh_token_grant(aws_env, monkeypatch):
    """brolly drives its own device login, so its own registration has to declare what it needs: the account scope
    it uses to list accounts and roles, and the refresh_token grant a blob carrying a refreshToken is redeemed
    under — without which botocore cannot renew and the session ends at the access token's 8 hours."""
    monkeypatch.setenv('AWS_CONFIG_FILE', str(aws_env))
    fake_oidc = _FakeOidc()
    _login(monkeypatch, _FakeKeyring(), oidc=fake_oidc)

    assert fake_oidc.registration_kwargs['scopes'] == ['sso:account:access']
    assert fake_oidc.registration_kwargs['grantTypes'] == [keychain._DEVICE_GRANT, 'refresh_token']
    assert fake_oidc.registration_kwargs['clientType'] == 'public'


def test_device_login_unions_configured_registration_scopes_with_the_minimum(aws_env, monkeypatch):
    monkeypatch.setenv('AWS_CONFIG_FILE', str(aws_env))
    fake_oidc = _FakeOidc()
    sso_config = {**_SSO_CONFIG, 'sso_registration_scopes': 'sso:account:access, codewhisperer:completions'}
    _login(monkeypatch, _FakeKeyring(), oidc=fake_oidc, sso_config=sso_config)

    # configured scopes are honoured, the required one is never dropped, and it is not listed twice
    assert fake_oidc.registration_kwargs['scopes'] == ['sso:account:access', 'codewhisperer:completions']


def test_registration_scopes_defaults_to_the_minimum_when_unconfigured():
    assert keychain._registration_scopes({}) == ['sso:account:access']
    assert keychain._registration_scopes({'sso_registration_scopes': ''}) == ['sso:account:access']


def test_device_login_warns_when_no_refresh_token_is_issued(aws_env, monkeypatch, capsys):
    monkeypatch.setenv('AWS_CONFIG_FILE', str(aws_env))
    fake_keyring = _FakeKeyring()
    _login(monkeypatch, fake_keyring, oidc=_FakeOidc(with_refresh_token=False))

    blob = _stored_blob(fake_keyring)
    assert 'refreshToken' not in blob  # nothing fabricated
    assert json.loads(keychain._sidecar_path(keychain._cache_key(_SESSION)).read_text())['refreshable'] is False
    err = capsys.readouterr().err
    assert 'no refresh token' in err and 'sso:account:access' in err  # loud, and says what to check


def test_secure_enable_reauthorizes_a_stored_token_that_cannot_renew(aws_env, monkeypatch, capsys):
    """A session secured before the refresh_token grant was requested must not be left stranded at 8 hours."""
    _write_config(aws_env, secure=False)
    fake_keyring = _FakeKeyring()
    stale = {'accessToken': 'stale-tok', 'expiresAt': (datetime.now(UTC) + timedelta(hours=8)).isoformat()}
    fake_keyring.set_password('brolly-sso', keychain._cache_key(_SESSION), json.dumps(stale))
    monkeypatch.setattr(keychain, '_import_keyring', lambda: fake_keyring)
    monkeypatch.setattr(keychain, '_autodetect_backend', lambda _: 'fake.Backend')
    monkeypatch.setattr(keychain, '_select_backend', lambda *a: None)
    monkeypatch.setattr(keychain, '_backend_label', lambda _: 'fake')
    monkeypatch.setattr(keychain, 'sleep', lambda _: None)
    monkeypatch.setattr(keychain.boto3, 'client', lambda *a, **k: _FakeOidc())

    full_config = botocore.session.Session().full_config
    keychain.cmd_secure_enable(_SESSION, full_config)

    blob = _stored_blob(fake_keyring)
    assert blob['refreshToken'] == 'refresh-tok'  # re-authorized rather than left as-is
    assert 'cannot renew silently' in capsys.readouterr().err


def test_secure_enable_keeps_a_stored_token_that_can_renew(aws_env, monkeypatch, capsys):
    _write_config(aws_env, secure=False)
    fake_keyring = _FakeKeyring()
    good = {**_live_blob(), 'refreshToken': 'already-good'}
    fake_keyring.set_password('brolly-sso', keychain._cache_key(_SESSION), json.dumps(good))
    monkeypatch.setattr(keychain, '_import_keyring', lambda: fake_keyring)
    monkeypatch.setattr(keychain, '_autodetect_backend', lambda _: 'fake.Backend')
    monkeypatch.setattr(keychain, '_select_backend', lambda *a: None)
    monkeypatch.setattr(keychain, '_backend_label', lambda _: 'fake')

    def no_login(*_a: object, **_k: object) -> None:
        raise AssertionError('a healthy token must not trigger another device login')

    monkeypatch.setattr(keychain, '_device_login', no_login)
    keychain.cmd_secure_enable(_SESSION, botocore.session.Session().full_config)

    blob = _stored_blob(fake_keyring)
    assert blob['refreshToken'] == 'already-good'  # untouched


def test_secure_enable_writes_the_secured_session_record(aws_env, monkeypatch):
    """Finding 1: without this record, a session whose profiles later all become skeletons would read as plaintext
    again — `enable` must write it, not just reshape the profiles."""
    _write_config(aws_env, secure=False)
    fake_keyring = _FakeKeyring()
    good = {**_live_blob(), 'refreshToken': 'already-good'}
    fake_keyring.set_password('brolly-sso', keychain._cache_key(_SESSION), json.dumps(good))
    monkeypatch.setattr(keychain, '_import_keyring', lambda: fake_keyring)
    monkeypatch.setattr(keychain, '_autodetect_backend', lambda _: 'fake.Backend')
    monkeypatch.setattr(keychain, '_select_backend', lambda *a: None)
    monkeypatch.setattr(keychain, '_backend_label', lambda _: 'fake')

    def no_login(*_a: object, **_k: object) -> None:
        raise AssertionError('a healthy token must not trigger another device login')

    monkeypatch.setattr(keychain, '_device_login', no_login)

    assert _SESSION not in keychain._read_config().get('secured_sessions', [])
    keychain.cmd_secure_enable(_SESSION, botocore.session.Session().full_config)
    assert _SESSION in keychain._read_config()['secured_sessions']


def test_secure_disable_removes_the_secured_session_record(aws_env, monkeypatch):
    _write_config(aws_env, secure=True)
    keychain._record_secured_session(_SESSION, True)
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: _FakeKeyring())

    assert _SESSION in keychain._read_config()['secured_sessions']
    keychain.cmd_secure_disable(_SESSION, botocore.session.Session().full_config)
    assert _SESSION not in keychain._read_config().get('secured_sessions', [])


def _stored_keychain_session(keyring_module: _FakeKeyring) -> str:
    """Put a live token and its sidecar in the fake keychain, as a genuinely secured session has — the delete branch
    of `disable` never runs against an empty one."""
    cache_key = keychain._cache_key(_SESSION)
    keyring_module.set_password('brolly-sso', cache_key, json.dumps(_live_blob()))
    keychain._write_sidecar(_SESSION, cache_key, (datetime.now(UTC) + timedelta(hours=8)).isoformat(), True)
    return cache_key


def test_secure_disable_writes_the_stock_keys_back_and_drops_the_brolly_ones(aws_env, monkeypatch, capsys):
    """The revert itself, on disk. This is the documented way out of secure mode, and a profile left carrying
    `credential_process` and no sso_account_id after it resolves nothing at all: brolly no longer holds its token,
    and botocore's SSO provider has nothing to activate on."""
    _write_config(aws_env, secure=True)
    keychain._record_secured_session(_SESSION, True)
    fake_keyring = _FakeKeyring()
    cache_key = _stored_keychain_session(fake_keyring)
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: fake_keyring)

    keychain.cmd_secure_disable(_SESSION, botocore.session.Session().full_config)

    cfg = botocore.session.Session(profile=_PROFILE).get_scoped_config()
    assert cfg['sso_account_id'] == _ACCOUNT  # back to the shape botocore's SSO credential provider activates on
    assert cfg['sso_role_name'] == _ROLE
    assert cfg['sso_session'] == _SESSION
    assert 'credential_process' not in cfg
    assert 'brolly_sso_account_id' not in cfg
    assert 'brolly_sso_role_name' not in cfg
    assert fake_keyring.get_password('brolly-sso', cache_key) is None  # the token really left the keychain
    assert not keychain._sidecar_path(cache_key).exists()
    assert _SESSION not in keychain._read_config().get('secured_sessions', [])
    assert '1 profile(s) back to the stock cache' in capsys.readouterr().out


def test_secure_disable_reverts_the_profiles_even_when_the_keychain_refuses(aws_env, monkeypatch, capsys):
    """Why the revert runs first and the token delete is allowed to fail: the usual reason to reach for `disable` is
    a backend that has stopped working — an uninstalled package, a gpg-agent that will not unlock — and a keychain
    that raises must not turn a completed revert into a failed command."""

    class Locked(_FakeKeyring):
        def delete_password(self, service: str, username: str) -> None:
            raise self.errors.KeyringError('the keyring is locked')

    _write_config(aws_env, secure=True)
    keychain._record_secured_session(_SESSION, True)
    fake_keyring = Locked()
    cache_key = _stored_keychain_session(fake_keyring)
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: fake_keyring)

    keychain.cmd_secure_disable(_SESSION, botocore.session.Session().full_config)  # must not raise

    cfg = botocore.session.Session(profile=_PROFILE).get_scoped_config()
    assert cfg['sso_account_id'] == _ACCOUNT
    assert cfg['sso_role_name'] == _ROLE
    assert 'credential_process' not in cfg
    assert 'brolly_sso_account_id' not in cfg
    assert _SESSION not in keychain._read_config().get('secured_sessions', [])  # never silently re-secured
    assert not keychain._sidecar_path(cache_key).exists()  # nothing reads the entry now, so nothing describes it
    captured = capsys.readouterr()
    assert _SESSION in captured.err and 'could not be removed' in captured.err  # named, not swallowed
    assert '1 profile(s) back to the stock cache' in captured.out


def test_secure_disable_removes_the_sidecar_even_when_no_keychain_entry_existed(aws_env, monkeypatch):
    """An interrupted disable (or a keychain wiped from outside) leaves the entry gone and its sidecar behind, and
    `ls` reads the sidecar — so it would go on reporting an expiry for a secret that no longer exists."""
    _write_config(aws_env, secure=True)
    cache_key = keychain._cache_key(_SESSION)
    keychain._write_sidecar(_SESSION, cache_key, (datetime.now(UTC) + timedelta(hours=8)).isoformat(), True)
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: _FakeKeyring())  # empty: nothing stored

    keychain.cmd_secure_disable(_SESSION, botocore.session.Session().full_config)

    assert not keychain._sidecar_path(cache_key).exists()


def test_secure_disable_explains_a_half_converted_profile_instead_of_raising(aws_env, monkeypatch, capsys):
    """A conversion interrupted between its two `aws configure set` calls leaves brolly_sso_account_id with no role
    under either name. There is nothing to revert it to, which is a sentence to print — not a KeyError traceback in
    the middle of the one command that gets a user out of secure mode."""
    aws_env.write_text(
        '\n'.join([
            '[sso-session corp]',
            'sso_start_url = https://corp.awsapps.com/start',
            'sso_region = us-east-1',
            '',
            f'[profile {_PROFILE}]',
            'sso_session = corp',
            'region = us-east-1',
            'brolly_sso_account_id = 222222222222',
            f'credential_process = brolly credential-process --profile {_PROFILE}',
        ])
        + '\n'
    )
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: _FakeKeyring())

    keychain.cmd_secure_disable(_SESSION, botocore.session.Session().full_config)

    assert botocore.session.Session(profile=_PROFILE).get_scoped_config() == {
        'sso_session': _SESSION,
        'region': 'us-east-1',
    }
    captured = capsys.readouterr()
    assert _PROFILE in captured.err
    assert 'brolly switch' in captured.err  # names the command that can finish it
    assert '0 profile(s) back to the stock cache' in captured.out  # and does not claim a revert it did not make


def test_purge_plaintext_token_removes_a_planted_file_and_reports_it(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('HOME', str(tmp_path))
    cache_dir = tmp_path / '.aws' / 'sso' / 'cache'
    cache_dir.mkdir(parents=True)
    token = cache_dir / f'{keychain._cache_key(_SESSION)}.json'
    token.write_text('{"accessToken": "plaintext-cruft", "refreshToken": "leaked"}')

    keychain._purge_plaintext_token(_SESSION, _SSO_CONFIG)

    assert not token.exists()
    assert f"removed plaintext token cache for session '{_SESSION}'" in capsys.readouterr().err


def test_purge_plaintext_token_is_silent_and_safe_when_nothing_to_remove(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('HOME', str(tmp_path))  # no ~/.aws/sso/cache at all
    keychain._purge_plaintext_token(_SESSION, _SSO_CONFIG)  # must not raise
    assert capsys.readouterr().err == ''


def test_purge_session_plaintext_removes_the_blob_when_nothing_still_needs_it(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('HOME', str(tmp_path))
    plaintext = keychain._plaintext_token_path(_SESSION)
    plaintext.parent.mkdir(parents=True)
    plaintext.write_text('{"accessToken": "stale", "refreshToken": "leaked"}')
    full_config = {'profiles': {_PROFILE: {'sso_session': _SESSION, 'brolly_sso_account_id': _ACCOUNT}}}

    keychain.purge_session_plaintext(_SESSION, full_config)

    assert not plaintext.exists()
    assert f"removed plaintext token cache for session '{_SESSION}'" in capsys.readouterr().err


def test_purge_session_plaintext_guards_the_file_while_a_stock_sibling_still_resolves_from_it(
    tmp_path, monkeypatch, capsys
):
    """The guard, and all it now covers: a stock sibling resolves its credentials out of this exact blob, so
    deleting it would break a working profile. Every user-facing command heals such a profile before purging
    (`cli._enter_secure_session`), so this stands for `credential-process` alone — see the test below."""
    monkeypatch.setenv('HOME', str(tmp_path))
    plaintext = keychain._plaintext_token_path(_SESSION)
    plaintext.parent.mkdir(parents=True)
    plaintext.write_text('{"accessToken": "stale", "refreshToken": "leaked"}')
    full_config = {
        'profiles': {_PROFILE: {'sso_session': _SESSION, 'sso_account_id': _ACCOUNT, 'sso_role_name': _ROLE}}
    }

    keychain.purge_session_plaintext(_SESSION, full_config)

    assert plaintext.is_file()  # left alone — the sibling still needs it
    err = capsys.readouterr().err
    assert _PROFILE in err
    assert f"session '{_SESSION}' is secured" in err


def test_credential_process_neither_heals_a_stock_sibling_nor_deletes_anything(aws_env, monkeypatch, capsys):
    """`credential-process` is spawned by the SDK on every cold credential resolution, non-interactively and with
    stdout owned by the credential JSON. It rewrites neither ~/.aws/config nor the filesystem: the stock sibling
    keeps its keys and the leaked blob keeps its bytes, and the report says so."""
    _write_mixed_config(aws_env)
    plaintext = _plant_plaintext_token()
    stale_bytes = plaintext.read_bytes()

    fake_keyring = _FakeKeyring()
    fake_keyring.set_password('brolly-sso', keychain._cache_key(_SESSION), json.dumps(_live_blob()))
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: fake_keyring)
    monkeypatch.setattr(keychain.boto3, 'client', lambda *a, **k: _FakeSso(0))

    keychain.cmd_credential_process(_PROFILE)

    assert plaintext.read_bytes() == stale_bytes
    assert 'sso_account_id' in botocore.session.Session(profile=_STOCK).get_scoped_config()  # never healed here
    assert f"session '{_SESSION}' is secured" in capsys.readouterr().err


def test_credential_process_reports_a_leaked_token_and_registration_without_removing_either(
    aws_env, monkeypatch, capsys
):
    """The posture this path keeps toward the filesystem, for the same reason it already kept it toward
    ~/.aws/config. Its guards only recognise consumers that exist as AWS profiles, so a third-party SSO helper, a
    script or a container mount reading that blob is invisible to them — and this runs unattended, spawned by
    whatever wanted credentials. So it names both files, deletes neither, and says the next brolly command clears
    them. stdout stays exactly the credential JSON the calling SDK parses: one object, nothing else."""
    _write_config(aws_env, secure=True)
    token = _plant_plaintext_token(client_id='client-corp')
    registration = _plant_registration(_UNRELATED_NAME, 'client-corp')

    fake_keyring = _FakeKeyring()
    fake_keyring.set_password('brolly-sso', keychain._cache_key(_SESSION), json.dumps(_live_blob()))
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: fake_keyring)
    monkeypatch.setattr(keychain.boto3, 'client', lambda *a, **k: _FakeSso(0))

    keychain.cmd_credential_process(_PROFILE)  # exits 0: no SystemExit at all

    captured = capsys.readouterr()
    assert json.loads(captured.out)['Version'] == 1  # the whole of stdout parses as the one credential object
    assert token.is_file()
    assert registration.is_file()
    assert 'its token and the OIDC client registration `aws sso login` cached with it' in captured.err
    assert str(token) in captured.err and str(registration) in captured.err  # names the files, not just the fact
    assert 'The next brolly command clears it' in captured.err  # not being ignored, just not acted on here


def test_purge_session_plaintext_is_a_cheap_noop_when_no_plaintext_file_exists(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('HOME', str(tmp_path))  # no ~/.aws/sso/cache at all

    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError('must not scan profiles past the one stat that finds nothing to purge')

    monkeypatch.setattr(keychain, '_stock_profiles', boom)
    keychain.purge_session_plaintext(_SESSION, {'profiles': {}})  # must not raise

    assert capsys.readouterr().err == ''


def test_purge_removes_the_client_registration_the_login_cached_beside_the_token(tmp_path, monkeypatch, capsys):
    """`aws sso login` leaves two credentials in ~/.aws/sso/cache, not one: the token blob, and the OIDC client
    registration it was minted under — a client secret with roughly a 90-day life. Secure mode leaves neither.

    The registration is planted under a name brolly cannot derive, so the only thing that can have identified it is
    the clientId the token blob carries — the route that matters in practice, since what brolly purges is a leaked
    token blob and the blob is what names its own registration.
    """
    monkeypatch.setenv('HOME', str(tmp_path))
    token = _plant_plaintext_token(client_id='client-corp')
    registration = _plant_registration(_UNRELATED_NAME, 'client-corp')

    keychain.purge_session_plaintext(_SESSION, _secure_session_config())

    assert not token.exists()
    assert not registration.exists()
    err = capsys.readouterr().err
    assert f"removed plaintext token cache for session '{_SESSION}'" in err
    assert f"removed the OIDC client registration `aws sso login` cached for session '{_SESSION}'" in err


def test_purge_removes_a_registration_under_the_name_the_aws_cli_derives_when_no_token_blob_is_left(
    tmp_path, monkeypatch, capsys
):
    """The second route, and the only one left once the token blob has already gone: the AWS CLI names the file
    ``sha1`` of a JSON object over the start URL, region, scopes and session name, all of which brolly can read
    back out of the sso-session. A file under that exact name which reads as a registration is this session's by
    construction — no clientId to compare it against required."""
    monkeypatch.setenv('HOME', str(tmp_path))
    registration = _plant_registration(_aws_cli_registration_key(), 'client-corp')

    keychain.purge_session_plaintext(_SESSION, _secure_session_config())

    assert not registration.exists()
    assert (
        f"removed the OIDC client registration `aws sso login` cached for session '{_SESSION}'"
        in capsys.readouterr().err
    )


def test_purge_derives_the_registration_name_from_the_sessions_configured_scopes(tmp_path, monkeypatch):
    """``sso_registration_scopes`` is part of what the AWS CLI hashes, and it goes in parsed — comma-split and
    stripped — not as the raw string. Hashing the raw value would miss the file on every session that sets it."""
    monkeypatch.setenv('HOME', str(tmp_path))
    sso_config = {**_SSO_CONFIG, 'sso_registration_scopes': 'sso:account:access, codewhisperer:completions'}
    registration = _plant_registration(_aws_cli_registration_key(sso_config=sso_config), 'client-corp')
    full_config = {'profiles': {}, 'sso_sessions': {_SESSION: sso_config}}

    keychain.purge_session_plaintext(_SESSION, full_config)

    assert not registration.exists()


def test_purge_leaves_another_sessions_client_registration_alone(tmp_path, monkeypatch, capsys):
    """The constraint that shapes the whole feature: deleting somebody else's registration is a worse failure than
    leaving one behind. A registration blob names no session at all, so one that matches neither this session's
    clientId nor the name the CLI derives for it is not this session's to touch."""
    monkeypatch.setenv('HOME', str(tmp_path))
    token = _plant_plaintext_token(client_id='client-corp')
    mine = _plant_registration(_aws_cli_registration_key(), 'client-corp')
    theirs = _plant_registration(_aws_cli_registration_key(_OTHER_SESSION), 'client-other')
    unattributable = _plant_registration(_UNRELATED_NAME, 'client-nobody-knows')

    keychain.purge_session_plaintext(_SESSION, _secure_session_config())

    assert not token.exists()
    assert not mine.exists()
    assert theirs.is_file()  # another session's client secret, and none of brolly's business
    assert unattributable.is_file()  # attributable to nothing, so left behind rather than deleted on a guess


def test_purge_never_deletes_a_token_blob_even_one_carrying_this_sessions_client_id(tmp_path, monkeypatch):
    """Token blobs carry a clientId too — the CLI caches the registration alongside the token — so a clientId match
    alone would let the purge reach another session's *token*, breaking a live session outright. Only a file with
    no accessToken is ever a registration, which is what keeps the match off them."""
    monkeypatch.setenv('HOME', str(tmp_path))
    _plant_plaintext_token(client_id='client-corp')
    others_token = _plant_plaintext_token(_OTHER_SESSION, client_id='client-corp')
    others_bytes = others_token.read_bytes()

    keychain.purge_session_plaintext(_SESSION, _secure_session_config())

    assert others_token.read_bytes() == others_bytes  # byte for byte, not merely still present


def test_purge_tolerates_files_in_the_cache_directory_it_cannot_read(tmp_path, monkeypatch, capsys):
    """~/.aws/sso/cache is the AWS CLI's directory and brolly is a guest in it: a half-written file, a stray note,
    a JSON document of the wrong shape, something unreadable. None of that may crash a purge, and none of it may
    be deleted either."""
    monkeypatch.setenv('HOME', str(tmp_path))
    token = _plant_plaintext_token(client_id='client-corp')
    registration = _plant_registration(_UNRELATED_NAME, 'client-corp')
    cache_dir = keychain._sso_cache_dir()
    junk = cache_dir / 'half-written.json'
    junk.write_text('{"clientId": "client-corp", "clientSec')
    not_an_object = cache_dir / 'a-list.json'
    not_an_object.write_text('[1, 2, 3]')
    a_directory = cache_dir / 'directory.json'
    a_directory.mkdir()
    unreadable = cache_dir / 'locked.json'
    unreadable.write_text(json.dumps({'clientId': 'client-corp', 'clientSecret': 's', 'expiresAt': 'x'}))
    unreadable.chmod(0o000)

    keychain.purge_session_plaintext(_SESSION, _secure_session_config())  # must not raise

    assert not token.exists()
    assert not registration.exists()  # the one it could read and attribute still went
    assert junk.is_file() and not_an_object.is_file() and a_directory.is_dir() and unreadable.is_file()


def test_purge_holds_the_registration_back_on_the_same_guard_as_the_token(tmp_path, monkeypatch, capsys):
    """The registration is not a second, unguarded delete: while a stock profile still resolves out of this
    session's cache the whole purge stands down, and the message says which files are still there rather than
    calling a client registration a token."""
    monkeypatch.setenv('HOME', str(tmp_path))
    token = _plant_plaintext_token(client_id='client-corp')
    registration = _plant_registration(_aws_cli_registration_key(), 'client-corp')
    full_config = {
        'profiles': {_STOCK: {'sso_session': _SESSION, 'sso_account_id': _ACCOUNT, 'sso_role_name': _ROLE}},
        'sso_sessions': {_SESSION: _SSO_CONFIG},
    }

    keychain.purge_session_plaintext(_SESSION, full_config)

    assert token.is_file()
    assert registration.is_file()
    err = capsys.readouterr().err
    assert 'its token and the OIDC client registration `aws sso login` cached with it' in err
    assert _STOCK in err


def test_device_login_purges_the_registration_the_previous_aws_login_left(aws_env, monkeypatch, capsys):
    """brolly's own device login caches no registration to disk, so anything it finds is an `aws sso login`
    leftover — and it has just replaced the token that leftover minted."""
    monkeypatch.setenv('AWS_CONFIG_FILE', str(aws_env))
    token = _plant_plaintext_token(client_id='client-corp')
    registration = _plant_registration(_UNRELATED_NAME, 'client-corp')

    _login(monkeypatch, _FakeKeyring(), oidc=_FakeOidc())

    assert not token.exists()
    assert not registration.exists()


def test_device_login_purges_a_planted_plaintext_token(aws_env, monkeypatch, capsys):
    monkeypatch.setenv('AWS_CONFIG_FILE', str(aws_env))
    plaintext = keychain._plaintext_token_path(_SESSION)
    plaintext.parent.mkdir(parents=True)
    plaintext.write_text('{"accessToken": "stale", "refreshToken": "leaked"}')

    _login(monkeypatch, _FakeKeyring(), oidc=_FakeOidc())

    assert not plaintext.is_file()
    assert f"removed plaintext token cache for session '{_SESSION}'" in capsys.readouterr().err


_SSO_CONFIG_FOR_TOKEN = {'sso_sessions': {_SESSION: _SSO_CONFIG}}


def test_ensure_secure_token_returns_the_live_token_without_a_device_login(aws_env):
    _write_config(aws_env, secure=True)
    fake_keyring = _FakeKeyring()
    fake_keyring.set_password('brolly-sso', keychain._cache_key(_SESSION), json.dumps(_live_blob()))

    def no_login(*_a: object, **_k: object) -> None:
        raise AssertionError('a live keychain token must not trigger a device login')

    token = keychain._ensure_secure_token(_PROFILE, _SESSION, _SSO_CONFIG_FOR_TOKEN, fake_keyring)
    assert token == 'access-tok'


def test_ensure_secure_token_runs_a_device_login_when_none_is_stored(aws_env, monkeypatch, capsys):
    _write_config(aws_env, secure=True)
    fake_keyring = _FakeKeyring()
    called: list[str] = []

    def fake_device_login(session_name, sso_config, cache) -> None:
        called.append(session_name)
        cache[keychain._cache_key(session_name)] = {
            'accessToken': 'fresh-tok',
            'expiresAt': (datetime.now(UTC) + timedelta(hours=8)).isoformat(),
        }

    monkeypatch.setattr(keychain, '_device_login', fake_device_login)
    token = keychain._ensure_secure_token(_PROFILE, _SESSION, _SSO_CONFIG_FOR_TOKEN, fake_keyring)

    assert called == [_SESSION]
    assert token == 'fresh-tok'
    assert 'no valid keychain token' in capsys.readouterr().err


def test_ensure_secure_token_exits_when_still_unresolvable_after_login(aws_env, monkeypatch):
    _write_config(aws_env, secure=True)
    fake_keyring = _FakeKeyring()
    monkeypatch.setattr(keychain, '_device_login', lambda *a, **k: None)  # a login that never stores a token

    with pytest.raises(SystemExit, match='could not obtain a valid SSO token'):
        keychain._ensure_secure_token(_PROFILE, _SESSION, _SSO_CONFIG_FOR_TOKEN, fake_keyring)


def test_cmd_secure_add_writes_secure_shape_without_activating_sso_credential_provider(aws_env, monkeypatch):
    """Same load-bearing invariant as test_secured_profile_deactivates_sso_credential_provider, plus the new
    profile must mirror a sibling's region/output rather than falling back to the sso-session's own region."""
    from botocore.credentials import ProfileProviderBuilder

    aws_env.write_text(
        '\n'.join([
            '[sso-session corp]',
            'sso_start_url = https://corp.awsapps.com/start',
            'sso_region = us-east-1',
            '',
            '[profile corp-prod]',
            'sso_session = corp',
            'region = eu-west-1',
            'output = yaml',
            'brolly_sso_account_id = 222222222222',
            'brolly_sso_role_name = AdministratorAccess',
            'credential_process = brolly credential-process --profile corp-prod',
            '',
        ])
    )
    fake_keyring = _FakeKeyring()
    fake_keyring.set_password('brolly-sso', keychain._cache_key(_SESSION), json.dumps(_live_blob()))
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: fake_keyring)
    monkeypatch.setattr(keychain, '_backend_label', lambda _: 'fake')
    new_account = {'accountId': '333333333333', 'accountName': 'corp-dev'}
    monkeypatch.setattr(keychain, '_pick_account_role', lambda *a, **k: (new_account, 'ReadOnly'))

    full_config = botocore.session.Session().full_config
    keychain.cmd_secure_add(_SESSION, 'corp-dev', full_config)

    cfg = botocore.session.Session(profile='corp-dev').get_scoped_config()
    assert cfg['sso_session'] == _SESSION
    assert cfg['region'] == 'eu-west-1'  # mirrors the sibling, not the sso-session's own region
    assert cfg['output'] == 'yaml'
    assert cfg['credential_process'] == 'brolly credential-process --profile corp-dev'
    assert cfg['brolly_sso_account_id'] == '333333333333'
    assert cfg['brolly_sso_role_name'] == 'ReadOnly'
    assert 'sso_account_id' not in cfg  # never even briefly activates the SSO credential provider
    assert 'sso_role_name' not in cfg

    builder = ProfileProviderBuilder(botocore.session.Session(profile='corp-dev'))
    assert builder._create_sso_provider('corp-dev').load() is None


def test_cmd_secure_add_purges_a_planted_plaintext_token(aws_env, monkeypatch, capsys):
    _write_config(aws_env, secure=True)  # corp-prod already secure; corp-dev is the new profile
    plaintext = keychain._plaintext_token_path(_SESSION)
    plaintext.parent.mkdir(parents=True)
    plaintext.write_text('{"accessToken": "stale"}')

    fake_keyring = _FakeKeyring()
    fake_keyring.set_password('brolly-sso', keychain._cache_key(_SESSION), json.dumps(_live_blob()))
    monkeypatch.setattr(keychain, '_configured_keyring', lambda: fake_keyring)
    monkeypatch.setattr(keychain, '_backend_label', lambda _: 'fake')
    new_account = {'accountId': '333333333333', 'accountName': 'corp-dev'}
    monkeypatch.setattr(keychain, '_pick_account_role', lambda *a, **k: (new_account, 'ReadOnly'))

    full_config = botocore.session.Session().full_config
    keychain.cmd_secure_add(_SESSION, 'corp-dev', full_config)

    assert not plaintext.is_file()
    assert f"removed plaintext token cache for session '{_SESSION}'" in capsys.readouterr().err

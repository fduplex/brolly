"""Tests for brolly's opt-in OS-keychain secure mode.

Everything here runs offline: `keyring` and the boto3 sso/sso-oidc clients are faked, and the AWS config lives in
a tmp file via ``AWS_CONFIG_FILE``. No real keychain, no network, no credentials.
"""

import json
import os
from datetime import UTC, datetime, timedelta
from hashlib import sha1

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


class _FakeKeyring:
    """Minimal in-memory stand-in for the `keyring` module (service, username) -> secret string."""

    class errors:
        class KeyringError(Exception):
            pass

        class PasswordDeleteError(KeyringError):
            pass

    def __init__(self) -> None:
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


@pytest.fixture
def aws_env(tmp_path, monkeypatch):
    cfg = tmp_path / 'config'
    monkeypatch.setenv('AWS_CONFIG_FILE', str(cfg))
    monkeypatch.delenv('AWS_PROFILE', raising=False)
    return cfg


def _live_blob() -> dict[str, str]:
    return {'accessToken': 'access-tok', 'expiresAt': (datetime.now(UTC) + timedelta(days=1)).isoformat()}


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


def test_cache_key_matches_botocore_convention():
    assert keychain._cache_key(_SESSION) == sha1(_SESSION.encode('utf-8')).hexdigest()


def test_backend_label_maps_known_and_unknown():
    def fake_get_keyring():
        cls = type('Keyring', (), {})
        cls.__module__ = 'keyring_pass'
        return cls()

    fake_module = type('m', (), {'get_keyring': staticmethod(fake_get_keyring)})
    assert keychain._backend_label(fake_module) == 'pass (gpg-agent)'

    def unknown_get_keyring():
        cls = type('WeirdBackend', (), {})
        cls.__module__ = 'some.other.vault'
        return cls()

    other = type('m', (), {'get_keyring': staticmethod(unknown_get_keyring)})
    assert keychain._backend_label(other) == 'some.other.vault.WeirdBackend'


def test_configured_keyring_reports_missing_backend(monkeypatch):
    import keyring
    import keyring.backends.fail

    monkeypatch.setattr(keyring, 'get_keyring', lambda: keyring.backends.fail.Keyring())
    with pytest.raises(SystemExit, match='no OS keychain backend'):
        keychain._configured_keyring()


def test_configured_keyring_applies_saved_backend(monkeypatch):
    keychain._write_config({'keyring_backend': 'some.pkg.Backend'})
    applied = []
    monkeypatch.setattr(keychain, '_import_keyring', lambda: object())
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
    assert keychain._autodetect_backend(object()) == 'keyring_pass.PasswordStoreBackend'


def test_autodetect_returns_none_when_nothing_usable(monkeypatch):
    monkeypatch.setattr(keychain, '_is_fail_backend', lambda kr: True)
    monkeypatch.setattr(keychain, '_pass_store_ready', lambda: False)
    assert keychain._autodetect_backend(object()) is None


def test_autodetect_uses_active_os_keychain(monkeypatch):
    monkeypatch.setattr(keychain, '_is_fail_backend', lambda kr: False)
    backend = type('Keyring', (), {})
    backend.__module__ = 'keyring.backends.macOS'
    fake = type('m', (), {'get_keyring': staticmethod(lambda: backend())})
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

    blob = json.loads(fake_keyring.get_password('brolly-sso', keychain._cache_key(_SESSION)))
    assert blob['accessToken'] == 'access-tok'
    assert blob['refreshToken'] == 'refresh-tok'  # needed for silent refresh later
    assert blob['clientId'] == 'cid'
    assert blob['clientSecret'] == 'csecret'
    assert 'registrationExpiresAt' in blob
    sidecar = keychain._sidecar_path(keychain._cache_key(_SESSION))
    assert sidecar.is_file()
    assert json.loads(sidecar.read_text())['refreshable'] is True


def test_device_login_registers_for_the_refresh_token_grant(aws_env, monkeypatch):
    """Load-bearing: without this scope and grant, IAM Identity Center returns no refresh token and the session
    is stranded at the access token's 8 hours regardless of the configured access-portal session duration."""
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

    blob = json.loads(fake_keyring.get_password('brolly-sso', keychain._cache_key(_SESSION)))
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

    blob = json.loads(fake_keyring.get_password('brolly-sso', keychain._cache_key(_SESSION)))
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

    blob = json.loads(fake_keyring.get_password('brolly-sso', keychain._cache_key(_SESSION)))
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


def test_purge_plaintext_token_removes_a_planted_file_and_reports_it(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('HOME', str(tmp_path))
    cache_dir = tmp_path / '.aws' / 'sso' / 'cache'
    cache_dir.mkdir(parents=True)
    token = cache_dir / f'{keychain._cache_key(_SESSION)}.json'
    token.write_text('{"accessToken": "plaintext-cruft", "refreshToken": "leaked"}')

    keychain._purge_plaintext_token(_SESSION)

    assert not token.exists()
    assert f"removed plaintext token cache for session '{_SESSION}'" in capsys.readouterr().err


def test_purge_plaintext_token_is_silent_and_safe_when_nothing_to_remove(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('HOME', str(tmp_path))  # no ~/.aws/sso/cache at all
    keychain._purge_plaintext_token(_SESSION)  # must not raise
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


def test_purge_session_plaintext_leaves_the_file_when_a_stock_sibling_profile_exists(tmp_path, monkeypatch, capsys):
    """The mixed-session guard: a stock sibling still resolves its credentials out of this exact blob, so deleting
    it would break a working profile with nothing but a browser login to get it back."""
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


def test_purge_session_plaintext_is_a_cheap_noop_when_no_plaintext_file_exists(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('HOME', str(tmp_path))  # no ~/.aws/sso/cache at all

    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError('must not scan profiles past the one stat that finds nothing to purge')

    monkeypatch.setattr(keychain, '_stock_profiles', boom)
    keychain.purge_session_plaintext(_SESSION, {'profiles': {}})  # must not raise

    assert capsys.readouterr().err == ''


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

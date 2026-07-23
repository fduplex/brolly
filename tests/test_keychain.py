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
    """Keep every test off the real ~/.aws/brolly (config + sidecars both live under the aws-config dir)."""
    monkeypatch.setenv('AWS_CONFIG_FILE', str(tmp_path / 'config'))


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

    def __init__(self, pending_rounds: int = 1) -> None:
        self._pending = pending_rounds

    def register_client(self, **_: object) -> dict[str, object]:
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
        return {'accessToken': 'access-tok', 'expiresIn': 28800, 'refreshToken': 'refresh-tok'}


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
    assert json.loads(sidecar.read_text()) == {'session': _SESSION, 'expiresAt': expires.isoformat()}

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
    with pytest.raises(SystemExit, match='brolly secure login'):
        keychain.cmd_credential_process(_PROFILE)


def test_device_login_stores_blob_and_sidecar(aws_env, monkeypatch):
    monkeypatch.setenv('AWS_CONFIG_FILE', str(aws_env))
    monkeypatch.setattr(keychain, 'sleep', lambda _: None)
    fake_oidc = _FakeOidc(pending_rounds=2)  # exercise the polling loop
    monkeypatch.setattr(keychain.boto3, 'client', lambda *a, **k: fake_oidc)

    fake_keyring = _FakeKeyring()
    cache = keychain._KeychainTokenCache(fake_keyring, _SESSION)
    keychain._device_login(_SESSION, 'https://corp.awsapps.com/start', 'us-east-1', cache)

    blob = json.loads(fake_keyring.get_password('brolly-sso', keychain._cache_key(_SESSION)))
    assert blob['accessToken'] == 'access-tok'
    assert blob['refreshToken'] == 'refresh-tok'  # needed for silent refresh later
    assert blob['clientId'] == 'cid'
    assert blob['clientSecret'] == 'csecret'
    assert 'registrationExpiresAt' in blob
    assert keychain._sidecar_path(keychain._cache_key(_SESSION)).is_file()

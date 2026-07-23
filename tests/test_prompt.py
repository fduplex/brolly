"""Tests for the `brolly ps1` prompt pill — filesystem-only, no keychain, no network."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from brolly import prompt

_SESSION = 'corp'
_PROFILE = 'corp-prod'


def _write_config(path, *, secure: bool, sso: bool = True) -> None:
    lines = ['[sso-session corp]', 'sso_start_url = https://corp.awsapps.com/start', '', '[profile corp-prod]']
    if sso:
        lines.append('sso_session = corp')
    lines.append('sso_account_name = corp-prod')
    if secure:
        lines += [
            'brolly_sso_account_id = 222222222222',
            'credential_process = brolly credential-process --profile corp-prod',
        ]
    else:
        lines.append('sso_account_id = 222222222222')
    path.write_text('\n'.join(lines) + '\n')


def _expiry_file(path, *, hours: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = (datetime.now(UTC) + timedelta(hours=hours)).isoformat()
    path.write_text(json.dumps({'session': _SESSION, 'expiresAt': stamp}))


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('AWS_CONFIG_FILE', str(tmp_path / 'config'))
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)
    return tmp_path


def _run(capsys) -> str:
    assert prompt.main() == 0
    return capsys.readouterr().out


def test_no_profile_prints_nothing(env, monkeypatch, capsys):
    monkeypatch.delenv('AWS_PROFILE')
    assert _run(capsys) == ''


def test_secure_profile_live_reads_sidecar(env, capsys):
    _write_config(env / 'config', secure=True)
    key = hashlib.sha1(_SESSION.encode()).hexdigest()
    _expiry_file(env / 'brolly' / f'{key}.json', hours=8)
    out = _run(capsys)
    assert f'48;5;{prompt._ACCENT}' in out  # live accent
    assert 'corp-prod · corp-prod' in out
    assert prompt._AWS in out and prompt._POWERLINE in out


def test_secure_profile_idle_when_lapsed(env, capsys):
    _write_config(env / 'config', secure=True)
    key = hashlib.sha1(_SESSION.encode()).hexdigest()
    _expiry_file(env / 'brolly' / f'{key}.json', hours=-1)
    out = _run(capsys)
    assert '48;5;240' in out  # idle grey
    assert prompt._CLOCK in out


def test_secure_profile_gone_without_sidecar(env, capsys):
    _write_config(env / 'config', secure=True)
    out = _run(capsys)
    assert f'48;5;{prompt._ALERT}' in out  # gone red
    assert prompt._CROSS in out


def test_plaintext_profile_uses_stock_cache(env, capsys):
    _write_config(env / 'config', secure=False)
    key = hashlib.sha1(_SESSION.encode()).hexdigest()
    _expiry_file(env / '.aws' / 'sso' / 'cache' / f'{key}.json', hours=8)
    out = _run(capsys)
    assert f'48;5;{prompt._ACCENT}' in out  # live, sourced from the plaintext cache


def test_non_sso_profile_is_plain(env, capsys):
    _write_config(env / 'config', secure=False, sso=False)
    out = _run(capsys)
    assert f'48;5;{prompt._SHOULDER}' in out  # plain grey
    assert _PROFILE in out


def test_account_falls_back_to_id_when_unnamed(env, capsys):
    (env / 'config').write_text(
        '[profile corp-prod]\nsso_session = corp\nbrolly_sso_account_id = 222222222222\n'
        'credential_process = brolly credential-process --profile corp-prod\n'
    )
    assert '222222222222' in _run(capsys)


def test_prompt_module_never_imports_boto3():
    """The pill runs on every prompt — importing boto3 here would cost ~70ms a render."""
    import subprocess
    import sys

    code = 'import sys, brolly.prompt; print("boto3" in sys.modules or "botocore" in sys.modules)'
    out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True).stdout.strip()
    assert out == 'False'

"""Tests for command dispatch: which command function runs, keyed off whether the sso-session is secure.

Secure mode became a property of the sso-session (not a profile) in this refactor, so every top-level command in
`cli.main` reads `_session_is_secure` and routes itself — there is no longer a separate `brolly secure login`. These
tests drive `cli.main` end to end with monkeypatched command functions and assert which one ran, and separately pin
down `_session_is_secure` itself, including the self-healing mixed-session case.
"""

import subprocess

import pytest

from brolly import cli, keychain

_SESSION = 'corp'
_PROFILE = 'corp-prod'


@pytest.fixture(autouse=True)
def _isolate_brolly_config(tmp_path, monkeypatch):
    """`_session_is_secure` reads brolly's own config (the secured-session record) and dispatch writes it, so no
    test here may see — let alone touch — the real ~/.aws, which holds live tokens."""
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('AWS_CONFIG_FILE', str(tmp_path / 'config'))


def _full_config(sessions: dict[str, str], profiles: dict[str, dict]) -> dict:
    return {
        'sso_sessions': {name: {'sso_region': region} for name, region in sessions.items()},
        'profiles': profiles,
    }


def _secure_profile(session: str, account_id: str = '111111111111', role: str = 'Admin') -> dict:
    return {'sso_session': session, 'brolly_sso_account_id': account_id, 'brolly_sso_role_name': role}


def _plain_profile(session: str, account_id: str = '111111111111', role: str = 'Admin') -> dict:
    return {'sso_session': session, 'sso_account_id': account_id, 'sso_role_name': role}


# --- _session_is_secure ------------------------------------------------------------------------


def test_session_is_secure_true_when_a_profile_is_secure():
    full_config = _full_config({_SESSION: 'us-east-1'}, {_PROFILE: _secure_profile(_SESSION)})
    assert cli._session_is_secure(_SESSION, full_config) is True


def test_session_is_secure_false_when_no_profile_is_secure():
    full_config = _full_config({_SESSION: 'us-east-1'}, {_PROFILE: _plain_profile(_SESSION)})
    assert cli._session_is_secure(_SESSION, full_config) is False


def test_session_is_secure_false_for_an_unknown_session():
    full_config = _full_config({_SESSION: 'us-east-1'}, {_PROFILE: _plain_profile(_SESSION)})
    assert cli._session_is_secure('ghost-session', full_config) is False


def test_session_is_secure_true_for_a_mixed_session():
    """Self-healing case: one profile secured, a sibling still plaintext — the session still reads secure, so a
    later `add`/`switch` under it takes the secure path too instead of drifting further apart."""
    full_config = _full_config(
        {_SESSION: 'us-east-1'},
        {'corp-a': _secure_profile(_SESSION, '111111111111'), 'corp-b': _plain_profile(_SESSION, '222222222222')},
    )
    assert cli._session_is_secure(_SESSION, full_config) is True


def test_session_is_secure_true_from_record_alone_with_zero_secure_shaped_profiles():
    """Finding 1, the exact shape: a session recorded as secured but with no profile carrying the secure shape —
    either because it has none at all, or because what it has are unfinished skeletons. Without the record, this
    would read as plaintext forever and the next `login` would write a fresh refresh token back to disk."""
    cli._record_secured_session(_SESSION, True)

    no_profiles = _full_config({_SESSION: 'us-east-1'}, {})
    assert cli._session_is_secure(_SESSION, no_profiles) is True

    skeleton_only = _full_config({_SESSION: 'us-east-1'}, {_PROFILE: {'sso_session': _SESSION}})
    assert cli._session_is_secure(_SESSION, skeleton_only) is True


def test_session_is_secure_fallback_still_works_with_no_record_at_all():
    """Back-compat: a session secured by an older brolly (no record ever written) must still read secure off the
    profile shape alone."""
    assert cli._secured_sessions() == set()  # nothing recorded — no config.json even written yet
    full_config = _full_config({_SESSION: 'us-east-1'}, {_PROFILE: _secure_profile(_SESSION)})
    assert cli._session_is_secure(_SESSION, full_config) is True


# --- the secured-session record -----------------------------------------------------------------


def test_secured_sessions_tolerates_a_malformed_config():
    cli._write_config({'secured_sessions': 'not-a-list'})  # non-list value
    assert cli._secured_sessions() == set()

    cli._write_config({})  # missing key entirely
    assert cli._secured_sessions() == set()

    cli._write_config({'secured_sessions': [123, None, 'corp', 'zeta']})  # non-string members mixed in
    assert cli._secured_sessions() == {'corp', 'zeta'}


def test_record_secured_session_is_best_effort_when_the_config_dir_is_unwritable(tmp_path):
    """`_record_secured_session` must never raise — brolly's own config is a nicety, not something worth failing
    a command over. Blocking the `brolly/` directory with a plain file makes the mkdir it needs fail with OSError,
    which the real code wraps in `suppress(OSError)`."""
    (tmp_path / 'brolly').write_text('not a directory')

    cli._record_secured_session(_SESSION, True)  # must not raise

    assert _SESSION not in cli._secured_sessions()  # the write never landed


# --- `brolly secure login` is gone -------------------------------------------------------------


def test_secure_login_subcommand_is_gone():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(['secure', 'login'])
    assert exc_info.value.code == 2  # argparse's invalid-choice exit


# --- dispatch routing ---------------------------------------------------------------------------


def _write_session_config(
    path, *, secure: bool, session: str = _SESSION, profile: str = _PROFILE, account: str = '111111111111'
) -> None:
    lines = [
        f'[sso-session {session}]',
        'sso_start_url = https://corp.awsapps.com/start',
        'sso_region = us-east-1',
        '',
        f'[profile {profile}]',
        f'sso_session = {session}',
        'region = us-east-1',
    ]
    if secure:
        lines += [
            f'brolly_sso_account_id = {account}',
            'brolly_sso_role_name = AdministratorAccess',
            f'credential_process = brolly credential-process --profile {profile}',
        ]
    else:
        lines += [f'sso_account_id = {account}', 'sso_role_name = AdministratorAccess']
    path.write_text('\n'.join(lines) + '\n')


@pytest.fixture
def dispatch_env(tmp_path, monkeypatch):
    """An isolated ~/.aws/config plus a stubbed `_require_aws` — dispatch itself never needs the real `aws` CLI."""
    monkeypatch.setenv('AWS_CONFIG_FILE', str(tmp_path / 'config'))
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.delenv('AWS_PROFILE', raising=False)
    monkeypatch.setattr(cli, '_require_aws', lambda: None)
    return tmp_path / 'config'


def test_login_dispatches_to_plaintext_path_on_a_plain_session(dispatch_env, monkeypatch):
    _write_session_config(dispatch_env, secure=False)
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(cli, 'cmd_login', lambda session: calls.append(('plain', session)))
    monkeypatch.setattr(keychain, 'cmd_secure_login', lambda *a, **k: calls.append(('secure', a)))

    cli.main(['login', '-s', _SESSION])

    assert calls == [('plain', _SESSION)]


def test_login_dispatches_to_secure_path_on_a_secure_session_and_never_reaches_plaintext(dispatch_env, monkeypatch):
    """The critical assertion: a secured session's `login` never runs the plaintext path that would rewrite a
    refresh token back into ~/.aws/sso/cache."""
    _write_session_config(dispatch_env, secure=True)
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(cli, 'cmd_login', lambda session: calls.append(('plain', session)))
    monkeypatch.setattr(keychain, 'cmd_secure_login', lambda session, full_config: calls.append(('secure', session)))

    cli.main(['login', '-s', _SESSION])

    assert calls == [('secure', _SESSION)]


def test_switch_dispatches_to_plaintext_path_when_current_profile_session_is_plain(dispatch_env, monkeypatch):
    _write_session_config(dispatch_env, secure=False)
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(cli, 'cmd_switch', lambda profile: calls.append(('plain', profile)))
    monkeypatch.setattr(keychain, 'cmd_secure_switch', lambda *a, **k: calls.append(('secure', a)))

    cli.main(['switch'])

    assert calls == [('plain', _PROFILE)]


def test_switch_dispatches_to_secure_path_when_current_profile_session_is_secure(dispatch_env, monkeypatch):
    _write_session_config(dispatch_env, secure=True)
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(cli, 'cmd_switch', lambda profile: calls.append(('plain', profile)))
    monkeypatch.setattr(keychain, 'cmd_secure_switch', lambda profile, full_config: calls.append(('secure', profile)))

    cli.main(['switch'])

    assert calls == [('secure', _PROFILE)]


def test_add_dispatches_to_plaintext_path_on_a_plain_session(dispatch_env, monkeypatch):
    _write_session_config(dispatch_env, secure=False)
    calls: list[tuple] = []
    monkeypatch.setattr(cli, 'cmd_add', lambda session, profile, full_config: calls.append(('plain', session, profile)))
    monkeypatch.setattr(keychain, 'cmd_secure_add', lambda *a, **k: calls.append(('secure', a)))

    cli.main(['add', 'corp-dev', '-s', _SESSION])

    assert calls == [('plain', _SESSION, 'corp-dev')]


def test_add_dispatches_to_secure_path_on_a_secure_session(dispatch_env, monkeypatch):
    _write_session_config(dispatch_env, secure=True)
    calls: list[tuple] = []
    monkeypatch.setattr(cli, 'cmd_add', lambda *a, **k: calls.append(('plain', a)))
    monkeypatch.setattr(
        keychain,
        'cmd_secure_add',
        lambda session, profile, full_config: calls.append(('secure', session, profile)),
    )

    cli.main(['add', 'corp-dev', '-s', _SESSION])

    assert calls == [('secure', _SESSION, 'corp-dev')]


def test_refresh_passes_the_sessions_secure_flag_to_cmd_refresh_on_a_plain_session(dispatch_env, monkeypatch):
    _write_session_config(dispatch_env, secure=False)
    calls: list[tuple] = []
    monkeypatch.setattr(
        cli, 'cmd_refresh', lambda target, session, full_config, secure=False: calls.append((target, session, secure))
    )

    cli.main(['refresh', _PROFILE, '-s', _SESSION])

    assert calls == [(_PROFILE, _SESSION, False)]


def test_refresh_passes_the_sessions_secure_flag_to_cmd_refresh_on_a_secure_session(dispatch_env, monkeypatch):
    _write_session_config(dispatch_env, secure=True)
    calls: list[tuple] = []
    monkeypatch.setattr(
        cli, 'cmd_refresh', lambda target, session, full_config, secure=False: calls.append((target, session, secure))
    )

    cli.main(['refresh', _PROFILE, '-s', _SESSION])

    assert calls == [(_PROFILE, _SESSION, True)]


def test_bare_brolly_defaults_to_refreshing_the_current_profile(dispatch_env, monkeypatch):
    """`main([])` is `brolly` with no arguments — it should behave exactly like `brolly refresh`."""
    _write_session_config(dispatch_env, secure=False)
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)
    calls: list[tuple] = []
    monkeypatch.setattr(
        cli, 'cmd_refresh', lambda target, session, full_config, secure=False: calls.append((target, session, secure))
    )

    cli.main([])

    assert calls == [(_PROFILE, _SESSION, False)]


def test_bare_brolly_passes_the_secure_flag_when_the_current_session_is_secure(dispatch_env, monkeypatch):
    _write_session_config(dispatch_env, secure=True)
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)
    calls: list[tuple] = []
    monkeypatch.setattr(
        cli, 'cmd_refresh', lambda target, session, full_config, secure=False: calls.append((target, session, secure))
    )

    cli.main([])

    assert calls == [(_PROFILE, _SESSION, True)]


def test_login_dispatches_to_secure_path_when_only_the_record_says_so(dispatch_env, monkeypatch):
    """The exact Finding 1 shape end to end: no profile under the session carries the secure shape, but brolly's
    own record does — `login` must still take the keychain path, not silently write a fresh plaintext refresh
    token because no profile gave it away."""
    dispatch_env.write_text(
        '\n'.join([
            f'[sso-session {_SESSION}]',
            'sso_start_url = https://corp.awsapps.com/start',
            'sso_region = us-east-1',
            '',
        ])
    )
    cli._record_secured_session(_SESSION, True)
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(cli, 'cmd_login', lambda session: calls.append(('plain', session)))
    monkeypatch.setattr(keychain, 'cmd_secure_login', lambda session, full_config: calls.append(('secure', session)))

    cli.main(['login', '-s', _SESSION])

    assert calls == [('secure', _SESSION)]


# --- purge at dispatch ---------------------------------------------------------------------------


def _plant_plaintext(session: str):
    """A stale plaintext token blob at botocore's fixed cache path — HOME is tmp_path-isolated by dispatch_env."""
    path = keychain._plaintext_token_path(session)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"accessToken": "stale", "refreshToken": "leaked"}')
    return path


def test_bare_brolly_purges_a_planted_plaintext_blob_on_a_secured_session(dispatch_env, monkeypatch):
    """The audit's own regression case: bare `brolly` used to leave the blob on disk because nothing but a command
    that actually authenticated ever cleared it."""
    _write_session_config(dispatch_env, secure=True)
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)
    plaintext = _plant_plaintext(_SESSION)
    monkeypatch.setattr(cli, 'cmd_refresh', lambda *a, **k: None)

    cli.main([])

    assert not plaintext.exists()


def test_login_purges_a_planted_plaintext_blob_on_a_secured_session(dispatch_env, monkeypatch):
    _write_session_config(dispatch_env, secure=True)
    plaintext = _plant_plaintext(_SESSION)
    monkeypatch.setattr(keychain, 'cmd_secure_login', lambda *a, **k: None)

    cli.main(['login', '-s', _SESSION])

    assert not plaintext.exists()


def test_switch_purges_a_planted_plaintext_blob_on_a_secured_session(dispatch_env, monkeypatch):
    """The audit measured that bare `brolly`, `ls`, and `switch` all previously left the plaintext blob on disk."""
    _write_session_config(dispatch_env, secure=True)
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)
    plaintext = _plant_plaintext(_SESSION)
    monkeypatch.setattr(keychain, 'cmd_secure_switch', lambda *a, **k: None)

    cli.main(['switch'])

    assert not plaintext.exists()


def test_add_purges_a_planted_plaintext_blob_on_a_secured_session(dispatch_env, monkeypatch):
    _write_session_config(dispatch_env, secure=True)
    plaintext = _plant_plaintext(_SESSION)
    monkeypatch.setattr(keychain, 'cmd_secure_add', lambda *a, **k: None)

    cli.main(['add', 'corp-dev', '-s', _SESSION])

    assert not plaintext.exists()


# --- cmd_refresh on a stock profile under a secured session --------------------------------------


def test_refresh_reports_a_stock_profile_under_a_secured_session_by_name(monkeypatch):
    """Fix 3: a stock profile under a secured session reads the now-empty plaintext cache, so logging in again
    cannot fix it — the error must name the profile, the session, and a concrete fix instead of retrying and
    surfacing botocore's raw SSOTokenLoadError."""
    monkeypatch.setattr(cli.subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 1, stdout='', stderr=''))
    full_config = _full_config({_SESSION: 'us-east-1'}, {_PROFILE: _plain_profile(_SESSION)})

    with pytest.raises(SystemExit) as exc_info:
        cli.cmd_refresh(_PROFILE, _SESSION, full_config, secure=True)

    message = str(exc_info.value)
    assert _PROFILE in message
    assert _SESSION in message
    assert 'brolly secure enable' in message  # a concrete fix, not just a diagnosis

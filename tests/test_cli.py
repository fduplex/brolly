"""Tests for command dispatch: which command function runs, keyed off whether the sso-session is secure.

Secure mode became a property of the sso-session (not a profile) in this refactor, so every top-level command in
`cli.main` reads `_session_is_secure` and routes itself — there is no longer a separate `brolly secure login`. These
tests drive `cli.main` end to end with monkeypatched command functions and assert which one ran, and separately pin
down `_session_is_secure` itself, including the self-healing mixed-session case.
"""

import stat
import subprocess
from collections.abc import Sequence

import botocore.session
import pytest

from brolly import cli, keychain

_SESSION = 'corp'
_PROFILE = 'corp-prod'
_STOCK = 'corp-legacy'
_SKELETON = 'corp-qa'
_STOCK_ACCOUNT = '999999999999'


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


def test_read_config_refuses_to_read_a_corrupt_config_as_an_empty_one():
    """Absent and unreadable are different answers. An absent config legitimately means "nothing is secured"; a
    corrupt one means brolly cannot tell — and answering "nothing" would route a secured session down the plaintext
    path, whose `login` writes a fresh refresh token into ~/.aws/sso/cache. So it fails loudly instead."""
    assert cli._read_config() == {}  # absent: legitimately empty

    path = cli._config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"secured_sessions": ["corp"\n')  # truncated mid-write: not JSON at all

    with pytest.raises(SystemExit) as exc_info:
        cli._read_config()

    assert str(path) in str(exc_info.value)  # names the file the user has to repair or delete


def test_read_config_refuses_a_json_document_that_is_not_an_object():
    """Well-formed JSON of the wrong shape is just as unusable: `.get(...)` on a list raises, and treating it as
    empty would hide a config brolly is about to overwrite."""
    path = cli._config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('["corp", "zeta"]\n')

    with pytest.raises(SystemExit, match='does not contain a JSON object'):
        cli._read_config()


def test_brolly_creates_its_own_directory_0700_with_0600_files():
    """Nothing in `~/.aws/brolly` is secret — a session name, an ISO expiry, a boolean, a backend path — but it
    sits next to botocore's own 0600 `~/.aws/sso/cache`, and being the loose file in the room is a downgrade
    nobody chose. Both files brolly writes there are covered: its config, and an expiry sidecar."""
    cli._write_config({'keyring_backend': 'x.Y'})
    keychain._write_sidecar(_SESSION, keychain._cache_key(_SESSION), '2026-07-27T00:00:00+00:00', True)

    directory = cli._config_path().parent
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(cli._config_path().stat().st_mode) == 0o600
    assert stat.S_IMODE(keychain._sidecar_path(keychain._cache_key(_SESSION)).stat().st_mode) == 0o600


def test_writing_tightens_a_directory_and_a_file_an_older_brolly_left_loose():
    """A mode chosen now only reaches the users who install brolly now unless existing state is tightened too —
    every one of these was created 0755/0644 by a brolly that never thought about it."""
    cli._write_config({'keyring_backend': 'x.Y'})
    path = cli._config_path()
    path.parent.chmod(0o755)
    path.chmod(0o644)

    cli._write_config({'keyring_backend': 'z.W'})

    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert cli._read_config() == {'keyring_backend': 'z.W'}  # tightened, and still the file it was rewriting


def test_atomic_write_still_preserves_the_mode_of_a_file_that_is_not_brollys(tmp_path):
    """The other side of that rule. `~/.aws/config` is the AWS CLI's file, brolly only edits lines in it — the
    rewrite goes through a temp file `mkstemp` creates at 0600, so without carrying the original's mode over it
    would silently re-permission a file whose mode was the user's to choose."""
    config = tmp_path / 'config'
    config.write_text('[profile corp-prod]\n')
    config.chmod(0o644)

    cli._atomic_write(config, '[profile corp-prod]\nregion = us-east-1\n')

    assert stat.S_IMODE(config.stat().st_mode) == 0o644
    assert config.read_text().endswith('region = us-east-1\n')


def test_write_config_leaves_the_original_file_intact_when_the_write_fails(monkeypatch):
    """The point of writing through a temp file: a write that dies part-way leaves the previous config, never a
    truncated one — a half-written record of which sessions are secured is exactly the file `_read_config` would
    then have to refuse to read."""
    cli._write_config({'keyring_backend': 'x.Y', 'secured_sessions': [_SESSION]})
    path = cli._config_path()
    original = path.read_text()

    def boom(*_args: object) -> None:
        raise OSError('no space left on device')

    monkeypatch.setattr(cli.os, 'replace', boom)

    with pytest.raises(OSError):
        cli._write_config({'keyring_backend': 'z.W'})

    assert path.read_text() == original
    assert cli._secured_sessions() == {_SESSION}  # still readable, still saying what it said
    assert list(path.parent.iterdir()) == [path]  # and no temp file left lying next to it


def test_record_secured_session_says_so_when_the_config_dir_is_unwritable(tmp_path):
    """A record brolly cannot write is not a nicety to swallow: the record is what routes a session to the keychain,
    so a silent failure ends with `secure enable` reporting success over a session the next `login` treats as
    plaintext. Blocking the `brolly/` directory with a plain file makes the mkdir it needs fail with OSError."""
    (tmp_path / 'brolly').write_text('not a directory')

    with pytest.raises(SystemExit) as exc_info:
        cli._record_secured_session(_SESSION, True)

    assert _SESSION in str(exc_info.value)
    assert str(tmp_path / 'brolly') in str(exc_info.value)  # names the file the user has to fix
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
    """An isolated ~/.aws/config plus stubs for the two things dispatch needs from outside: the real `aws` CLI, and
    a reachable OS keychain (`_enter_secure_session` proves the backend works before it rewrites anything, and no
    test machine is guaranteed one)."""
    monkeypatch.setenv('AWS_CONFIG_FILE', str(tmp_path / 'config'))
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.delenv('AWS_PROFILE', raising=False)
    monkeypatch.setattr(cli, '_require_aws', lambda: None)
    monkeypatch.setattr(keychain, 'preflight_keychain', lambda session_name: None)
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


# --- auto-heal at dispatch -----------------------------------------------------------------------


def _write_mixed_session_config(path, *, stock: Sequence[str] = (_STOCK,), skeletons: Sequence[str] = ()) -> None:
    """A secured session with one converted profile plus the shapes an upgrade can strand under it: profiles still
    carrying the stock SSO keys, and skeletons with no account/role picked yet."""
    lines = [
        f'[sso-session {_SESSION}]',
        'sso_start_url = https://corp.awsapps.com/start',
        'sso_region = us-east-1',
        '',
        f'[profile {_PROFILE}]',
        f'sso_session = {_SESSION}',
        'region = us-east-1',
        'brolly_sso_account_id = 111111111111',
        'brolly_sso_role_name = AdministratorAccess',
        f'credential_process = brolly credential-process --profile {_PROFILE}',
    ]
    for profile in stock:
        lines += [
            '',
            f'[profile {profile}]',
            f'sso_session = {_SESSION}',
            'region = us-east-1',
            f'sso_account_id = {_STOCK_ACCOUNT}',
            'sso_role_name = ReadOnly',
            f'sso_account_name = {profile}-acct',
        ]
    for profile in skeletons:
        lines += ['', f'[profile {profile}]', f'sso_session = {_SESSION}', 'region = us-east-1']
    path.write_text('\n'.join(lines) + '\n')


@pytest.fixture
def stubbed_commands(monkeypatch):
    """Stub out every command body a dispatching run could reach — these tests are about what
    `_enter_secure_session` does before any of them runs, not about the commands themselves."""
    monkeypatch.setattr(cli, 'cmd_refresh', lambda *a, **k: None)
    for name in ('cmd_secure_login', 'cmd_secure_switch', 'cmd_secure_add'):
        monkeypatch.setattr(keychain, name, lambda *a, **k: None)


_DISPATCHING_COMMANDS = [
    pytest.param([], id='bare-brolly'),
    pytest.param(['refresh'], id='refresh'),
    pytest.param(['login', '-s', _SESSION], id='login'),
    pytest.param(['switch'], id='switch'),
    pytest.param(['add', 'corp-new', '-s', _SESSION], id='add'),
]


@pytest.mark.parametrize('argv', _DISPATCHING_COMMANDS)
def test_every_dispatching_command_heals_a_stock_sibling_and_then_purges(
    argv, dispatch_env, monkeypatch, stubbed_commands, capsys
):
    """The mixed session, closed: a stock sibling rotates a live refresh token through ~/.aws/sso/cache on every
    refresh, so every command that routes into a secured session converts it — and only then may purge the blob."""
    _write_mixed_session_config(dispatch_env)
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)
    plaintext = _plant_plaintext(_SESSION)

    cli.main(argv)

    cfg = botocore.session.Session(profile=_STOCK).get_scoped_config()
    assert cfg['brolly_sso_account_id'] == _STOCK_ACCOUNT
    assert cfg['brolly_sso_role_name'] == 'ReadOnly'
    assert cfg['credential_process'] == f'brolly credential-process --profile {_STOCK}'
    assert 'sso_account_id' not in cfg  # the SSO credential-provider trigger is gone
    assert 'sso_role_name' not in cfg
    assert _STOCK in capsys.readouterr().err  # never silent: the profile brolly rewrote unasked is named
    assert not plaintext.exists()  # healing removed the last reader, so the purge no longer holds back


def test_healing_names_every_profile_it_rewrites(dispatch_env, monkeypatch, stubbed_commands, capsys):
    _write_mixed_session_config(dispatch_env, stock=[_STOCK, 'corp-old'])
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)

    cli.main([])

    healed = [line for line in capsys.readouterr().err.splitlines() if 'converted' in line]
    assert len(healed) == 2  # one line each, not a summary count
    assert any(_STOCK in line for line in healed)
    assert any('corp-old' in line for line in healed)


def test_a_skeleton_is_left_alone_and_never_blocks_the_purge(dispatch_env, monkeypatch, stubbed_commands, capsys):
    """A skeleton has no account/role to move, so healing cannot touch it — and it never activated botocore's SSO
    credential provider either, so it was not reading the blob and must not keep it on disk."""
    _write_mixed_session_config(dispatch_env, stock=[], skeletons=[_SKELETON])
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)
    plaintext = _plant_plaintext(_SESSION)

    cli.main([])

    cfg = botocore.session.Session(profile=_SKELETON).get_scoped_config()
    assert cfg == {'sso_session': _SESSION, 'region': 'us-east-1'}  # untouched
    assert _SKELETON not in capsys.readouterr().err
    assert not plaintext.exists()


def test_a_healed_profile_deactivates_the_sso_credential_provider(dispatch_env, monkeypatch, stubbed_commands):
    """The load-bearing invariant, re-asserted on the profile healing rewrote: botocore's SSO credential provider
    must skip it so resolution falls through to `credential_process`."""
    from botocore.credentials import ProfileProviderBuilder

    _write_mixed_session_config(dispatch_env)
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)

    cli.main([])

    builder = ProfileProviderBuilder(botocore.session.Session(profile=_STOCK))
    assert builder._create_sso_provider(_STOCK).load() is None


def test_a_skeleton_never_activates_the_sso_credential_provider(dispatch_env):
    """Why leaving skeletons alone is safe rather than merely unavoidable — with neither account nor role the SSO
    provider skips, so a skeleton never resolved from ~/.aws/sso/cache in the first place."""
    from botocore.credentials import ProfileProviderBuilder

    _write_mixed_session_config(dispatch_env, stock=[], skeletons=[_SKELETON])

    builder = ProfileProviderBuilder(botocore.session.Session(profile=_SKELETON))
    assert builder._create_sso_provider(_SKELETON).load() is None


# --- nothing is mutated before the command is known to be able to run -----------------------------


def _never_runs(*_a: object, **_k: object) -> None:
    raise AssertionError('no command body may run once dispatch has decided the command cannot proceed')


@pytest.mark.parametrize('argv', [pytest.param([], id='bare-brolly'), pytest.param(['refresh'], id='refresh')])
def test_an_unusable_keychain_stops_a_secured_session_before_anything_is_mutated(argv, tmp_path, monkeypatch):
    """`_enter_secure_session` proves the keychain is reachable *first*: everything after the preflight rewrites
    ~/.aws/config, records the session or deletes a token on the strength of a backend that must therefore be known
    to work. Deliberately does not use `dispatch_env`, whose no-op `preflight_keychain` stub hides that ordering —
    a run that cannot reach the keychain must leave the session exactly as it found it.
    """
    config = tmp_path / 'config'
    _write_mixed_session_config(config)
    before = config.read_text()
    plaintext = _plant_plaintext(_SESSION)
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)
    monkeypatch.setattr(cli, '_require_aws', lambda: None)
    monkeypatch.setattr(cli, 'cmd_refresh', _never_runs)

    def unusable(_session_name: str) -> None:
        raise SystemExit('no OS keychain backend is available')

    monkeypatch.setattr(keychain, 'preflight_keychain', unusable)

    with pytest.raises(SystemExit, match='no OS keychain backend'):
        cli.main(argv)

    assert config.read_text() == before  # not healed: the stock sibling still carries its stock keys
    assert plaintext.read_text() == '{"accessToken": "stale", "refreshToken": "leaked"}'  # not purged
    assert cli._secured_sessions() == set()  # not recorded
    assert not cli._config_path().exists()


def test_refresh_under_the_wrong_session_fails_before_it_heals_or_purges(dispatch_env, monkeypatch):
    """Arguments are validated before the secure door opens: a mistyped `-s` names a session brolly would otherwise
    heal and purge on its way to failing — mutating a session the user never meant to operate on."""
    dispatch_env.write_text(
        '\n'.join([
            f'[sso-session {_SESSION}]',
            'sso_start_url = https://corp.awsapps.com/start',
            'sso_region = us-east-1',
            '',
            f'[profile {_PROFILE}]',
            f'sso_session = {_SESSION}',
            'brolly_sso_account_id = 111111111111',
            'brolly_sso_role_name = AdministratorAccess',
            f'credential_process = brolly credential-process --profile {_PROFILE}',
            '',
            f'[profile {_STOCK}]',
            f'sso_session = {_SESSION}',
            f'sso_account_id = {_STOCK_ACCOUNT}',
            'sso_role_name = ReadOnly',
            '',
            '[sso-session other]',
            'sso_start_url = https://other.awsapps.com/start',
            'sso_region = us-east-1',
            '',
            '[profile other-prod]',
            'sso_session = other',
            'sso_account_id = 888888888888',
            'sso_role_name = ReadOnly',
            '',
        ])
    )
    before = dispatch_env.read_text()
    plaintext = _plant_plaintext(_SESSION)
    monkeypatch.setattr(cli, 'cmd_refresh', _never_runs)

    with pytest.raises(SystemExit, match="profile 'other-prod' is under session 'other'"):
        cli.main(['refresh', 'other-prod', '-s', _SESSION])

    assert dispatch_env.read_text() == before
    assert plaintext.exists()
    assert cli._secured_sessions() == set()


def test_add_of_an_existing_profile_fails_before_it_heals_or_purges(dispatch_env, monkeypatch):
    """Same rule for `add`: the name clash is knowable without touching anything, so nothing is touched."""
    _write_mixed_session_config(dispatch_env)
    before = dispatch_env.read_text()
    plaintext = _plant_plaintext(_SESSION)
    monkeypatch.setattr(keychain, 'cmd_secure_add', _never_runs)

    with pytest.raises(SystemExit, match=f"profile '{_PROFILE}' already exists"):
        cli.main(['add', _PROFILE, '-s', _SESSION])

    assert dispatch_env.read_text() == before
    assert plaintext.exists()
    assert cli._secured_sessions() == set()


def test_switch_under_an_undefined_session_fails_before_it_heals_or_purges(dispatch_env, monkeypatch):
    """`switch` takes its session from the current profile, so an undefined one is a config error rather than a
    typo — and still not a reason to have already rewritten the profiles under it."""
    dispatch_env.write_text(
        '\n'.join([
            f'[profile {_PROFILE}]',
            'sso_session = ghost',
            'brolly_sso_account_id = 111111111111',
            'brolly_sso_role_name = AdministratorAccess',
            f'credential_process = brolly credential-process --profile {_PROFILE}',
            '',
            f'[profile {_STOCK}]',
            'sso_session = ghost',
            f'sso_account_id = {_STOCK_ACCOUNT}',
            'sso_role_name = ReadOnly',
            '',
        ])
    )
    before = dispatch_env.read_text()
    plaintext = _plant_plaintext('ghost')
    monkeypatch.setenv('AWS_PROFILE', _PROFILE)
    monkeypatch.setattr(keychain, 'cmd_secure_switch', _never_runs)

    with pytest.raises(SystemExit, match="unknown sso-session 'ghost'"):
        cli.main(['switch'])

    assert dispatch_env.read_text() == before
    assert plaintext.exists()


# --- cmd_refresh on a profile that is not in secure shape under a secured session -----------------


def test_refresh_points_a_skeleton_under_a_secured_session_at_switch(monkeypatch):
    """Healing converts every stock profile before `refresh` runs, and one it could not convert keeps its brolly
    keys and so reads as secure — which leaves the skeleton as the only case that reaches this, and `secure enable`
    cannot finish that either, so the message has to name the command that can."""
    monkeypatch.setattr(cli.subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 1, stdout='', stderr=''))
    full_config = _full_config({_SESSION: 'us-east-1'}, {_SKELETON: {'sso_session': _SESSION}})

    with pytest.raises(SystemExit) as exc_info:
        cli.cmd_refresh(_SKELETON, _SESSION, full_config, secure=True)

    message = str(exc_info.value)
    assert _SKELETON in message
    assert 'brolly switch' in message
    assert 'secure enable' not in message  # it would report this profile as left alone, not fix it

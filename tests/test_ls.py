"""Tests for the `brolly ls` command — grouped session/profile listing with local or network-probed liveness."""

import hashlib
import json
import re
import sys
from datetime import UTC, datetime, timedelta

import pytest

from brolly import cli

_ALPHA = 'alpha'
_ZETA = 'zeta'


def _full_config(sessions: dict[str, str], profiles: dict[str, dict]) -> dict:
    return {
        'sso_sessions': {name: {'sso_region': region} for name, region in sessions.items()},
        'profiles': profiles,
    }


def _plaintext_profile(session: str, account_id: str, role: str) -> dict:
    return {'sso_session': session, 'sso_account_id': account_id, 'sso_role_name': role, 'region': 'us-east-1'}


def _secure_profile(session: str, account_id: str, role: str) -> dict:
    return {
        'sso_session': session,
        'brolly_sso_account_id': account_id,
        'brolly_sso_role_name': role,
        'region': 'us-east-1',
    }


def _expiry_file(path, *, hours: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = (datetime.now(UTC) + timedelta(hours=hours)).isoformat()
    path.write_text(json.dumps({'expiresAt': stamp}))


def _plaintext_cache_path(home, session: str):
    key = hashlib.sha1(session.encode('utf-8')).hexdigest()
    return home / '.aws' / 'sso' / 'cache' / f'{key}.json'


def _secure_sidecar_path(config_dir, session: str):
    key = hashlib.sha1(session.encode('utf-8')).hexdigest()
    return config_dir / 'brolly' / f'{key}.json'


def _no_probe(*_args: object, **_kwargs: object) -> None:
    raise AssertionError('_probe_session must not be called under --no-check')


def _sections(out: str) -> list[str]:
    """Split ls output into one chunk per sso-session — header, dim rule, and the trailing footer are dropped.

    Output is one contiguous table: a leading blank line, a worded header row, a dim rule, then one block per
    session (a session line followed by its profile rows) with a blank line closing each block, then a single
    $AWS_PROFILE footer line and a final blank line. Session lines no longer carry the _AWS lead glyph, so we drop
    the first three lines, split the remaining body on blank rows, and drop the footer block (the one naming
    $AWS_PROFILE) so a caller can index sections by session.
    """
    blocks: list[list[str]] = []
    for line in out.splitlines()[3:]:  # drop the leading blank line, the header row, and the rule
        if line == '':
            if blocks and blocks[-1]:
                blocks.append([])
        else:
            if not blocks:
                blocks.append([])
            blocks[-1].append(line)
    return ['\n'.join(block) for block in blocks if block and 'AWS_PROFILE' not in '\n'.join(block)]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('AWS_CONFIG_FILE', str(tmp_path / 'config'))
    return tmp_path


def test_ls_groups_and_sorts_profiles_under_each_session(env, capsys):
    full_config = _full_config(
        {_ZETA: 'us-west-2', _ALPHA: 'us-east-1'},
        {
            'zeta-prod': _plaintext_profile(_ZETA, '111111111111', 'AdministratorAccess'),
            'zeta-dev': _secure_profile(_ZETA, '222222222222', 'ReadOnly'),
            'alpha-ops': _plaintext_profile(_ALPHA, '333333333333', 'Ops'),
        },
    )
    cli.cmd_ls(full_config, 'none', False)
    sections = _sections(capsys.readouterr().out)

    assert len(sections) == 2
    assert sections[0].startswith(f'   {_ALPHA}')  # sso-sessions sorted alphabetically; 3-space indent, no _AWS lead
    assert sections[1].startswith(f'   {_ZETA}')
    assert cli._AWS not in sections[0] and cli._AWS not in sections[1]  # the AWS glyph now lives only in the heading
    assert 'alpha-ops' in sections[0]
    assert 'alpha-ops' not in sections[1]
    assert 'zeta-dev' in sections[1] and 'zeta-prod' in sections[1]
    assert 'zeta-dev' not in sections[0] and 'zeta-prod' not in sections[0]
    assert sections[1].index('zeta-dev') < sections[1].index('zeta-prod')  # profiles sorted within a session


def test_ls_starts_with_blank_line_then_worded_header_row(env, capsys):
    full_config = _full_config(
        {_ALPHA: 'us-east-1'},
        {'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'Admin')},
    )
    cli.cmd_ls(full_config, 'none', False)
    lines = capsys.readouterr().out.splitlines()

    assert lines[0] == ''  # leading blank line before anything else
    header = lines[1]  # header row precedes the rule and the first session line
    assert all(word in header for word in ('session', 'status', 'profile', 'secure', 'account', 'role', 'region'))
    # every heading now pairs a glyph with its word: session (AWS), status (heartbeat), profile (user), + attributes
    assert all(g in header for g in (cli._AWS, cli._PULSE, cli._USER, cli._LOCK, cli._ACCT, cli._ROLE, cli._GLOBE))
    assert header.index('session') < header.index('status') < header.index('profile')  # heading order
    assert cli._CURRENT not in header  # no marker column: the current profile is flagged by an orange name, not a glyph
    assert set(lines[2].strip()) == {'─'}  # a rule sits directly under the header
    assert lines[3].startswith(f'   {_ALPHA}')  # first session line follows the rule, indented, no _AWS lead
    assert not lines[3].startswith(cli._AWS)


def test_ls_secure_column_uses_check_for_secure_and_cross_for_plain(env, capsys):
    full_config = _full_config(
        {_ALPHA: 'us-east-1'},
        {
            'alpha-secure': _secure_profile(_ALPHA, '1' * 12, 'Admin'),
            'alpha-plain': _plaintext_profile(_ALPHA, '2' * 12, 'Admin'),
        },
    )
    cli.cmd_ls(full_config, 'none', False)
    lines = capsys.readouterr().out.splitlines()

    secure_row = next(line for line in lines if 'alpha-secure' in line)
    plain_row = next(line for line in lines if 'alpha-plain' in line)
    assert cli._CHECK in secure_row and cli._CROSS not in secure_row
    assert cli._CROSS in plain_row and cli._CHECK not in plain_row


def test_ls_secure_cell_is_centered_in_its_column(env, monkeypatch, capsys):
    full_config = _full_config(
        {_ALPHA: 'us-east-1'},
        {'alpha-secure': _secure_profile(_ALPHA, '1' * 12, 'Admin')},
    )
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: False)
    cli.cmd_ls(full_config, 'none', False)
    row = next(line for line in capsys.readouterr().out.splitlines() if 'alpha-secure' in line)

    # secure width is the heading '🔒 secure' (8); a lone glyph centres to 3 spaces + glyph + 4 spaces, not flush-left
    assert f'   {cli._CHECK}    ' in row
    assert f'{cli._CHECK}       ' not in row  # would be the left-justified rendering


def test_ls_ends_with_blank_row_after_every_session_group(env, capsys):
    full_config = _full_config(
        {_ALPHA: 'us-east-1', _ZETA: 'us-west-2'},
        {
            'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'Admin'),
            'zeta-a': _plaintext_profile(_ZETA, '2' * 12, 'Admin'),
        },
    )
    cli.cmd_ls(full_config, 'none', False)
    lines = capsys.readouterr().out.split('\n')

    assert lines[-1] == ''  # str.split leaves one final '' after the trailing newline
    assert lines[-2] == ''  # the final print('') after the footer, so output ends on a blank row
    # a blank row separates the two session groups: exactly one empty line sits between them
    sessions = [i for i, line in enumerate(lines) if line.startswith(f'   {_ALPHA}') or line.startswith(f'   {_ZETA}')]
    assert lines[sessions[1] - 1] == ''


def test_no_check_classifies_live_and_idle_from_local_state_only(env, monkeypatch, capsys):
    full_config = _full_config(
        {_ALPHA: 'us-east-1', _ZETA: 'us-west-2'},
        {
            'alpha-prod': _plaintext_profile(_ALPHA, '111111111111', 'AdministratorAccess'),
            'zeta-prod': _secure_profile(_ZETA, '222222222222', 'AdministratorAccess'),
        },
    )
    _expiry_file(_plaintext_cache_path(env, _ALPHA), hours=8)  # future -> live
    _expiry_file(_secure_sidecar_path(env, _ZETA), hours=-2)  # past -> idle

    monkeypatch.setattr(cli, '_probe_session', _no_probe)
    cli.cmd_ls(full_config, 'none', False)
    sections = _sections(capsys.readouterr().out)

    assert 'live' in sections[0] and 'expires' in sections[0]
    assert 'idle' in sections[1] and 'expired' in sections[1]
    assert re.search(r'\(-?\d+h\d{2}m\)|\(-?\d+m\)', sections[0] + sections[1])  # a countdown rendered


def test_check_probes_only_idle_sessions_and_the_probe_result_wins(env, monkeypatch, capsys):
    full_config = _full_config(
        {'alive': 'us-east-1', 'dead': 'us-east-1', 'lapsed': 'us-east-1'},
        {
            'alive-prof': _plaintext_profile('alive', '1' * 12, 'Admin'),
            'dead-prof': _plaintext_profile('dead', '2' * 12, 'Admin'),
            'lapsed-prof': _plaintext_profile('lapsed', '3' * 12, 'Admin'),
        },
    )
    _expiry_file(_plaintext_cache_path(env, 'alive'), hours=8)  # live locally
    # 'dead' has no expiry file at all -> gone locally
    _expiry_file(_plaintext_cache_path(env, 'lapsed'), hours=-3)  # idle locally

    probed: list[str] = []

    def fake_probe(session_name, profile, secure, keychain_mod, keyring_module):
        probed.append(session_name)
        return 'gone', None

    monkeypatch.setattr(cli, '_probe_session', fake_probe)
    cli.cmd_ls(full_config, 'none', True)
    sections = _sections(capsys.readouterr().out)

    assert probed == ['lapsed']  # only the locally-idle session triggers a network probe
    assert 'live' in sections[0] and 'expires' in sections[0]  # alive: untouched by probe
    assert 'gone' in sections[1] and 'no valid token' in sections[1]  # dead: already gone, no probe needed
    assert 'gone' in sections[2] and 'no valid token' in sections[2]  # lapsed: probe overrode the local idle read
    assert 'idle' not in sections[2]


def test_current_profile_name_is_orange_on_tty_only_for_the_match(env, monkeypatch, capsys):
    full_config = _full_config(
        {_ALPHA: 'us-east-1'},
        {
            'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'Admin'),
            'alpha-b': _plaintext_profile(_ALPHA, '2' * 12, 'Admin'),
        },
    )
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: True)
    cli.cmd_ls(full_config, 'alpha-b', False)
    lines = capsys.readouterr().out.splitlines()

    row_a = next(line for line in lines if 'alpha-a' in line)
    row_b = next(line for line in lines if 'alpha-b' in line and 'AWS_PROFILE' not in line)  # the row, not the footer
    assert f'{cli._ORANGE}alpha-b{cli._RESET}' in row_b  # current profile's name carries the orange
    assert cli._ORANGE not in row_a  # a non-current profile row stays plain (its only colour is the secure glyph)
    assert cli._CURRENT not in row_a and cli._CURRENT not in row_b  # marker column removed entirely


def test_current_profile_name_has_no_ansi_off_tty(env, monkeypatch, capsys):
    full_config = _full_config({_ALPHA: 'us-east-1'}, {'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'Admin')})
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: False)
    cli.cmd_ls(full_config, 'alpha-a', False)
    row = next(line for line in capsys.readouterr().out.splitlines() if 'alpha-a' in line and 'AWS_PROFILE' not in line)

    assert '\033[' not in row  # current-name highlight is TTY-gated; off a TTY the name is plain
    assert row.index('alpha-a') > 0 and cli._CURRENT not in row


def test_profile_names_share_one_fixed_offset_with_no_marker_column(env, monkeypatch, capsys):
    full_config = _full_config(
        {_ALPHA: 'us-east-1', _ZETA: 'us-west-2'},
        {
            'alpha-current': _plaintext_profile(_ALPHA, '1' * 12, 'Admin'),  # the current profile
            'alpha-other': _plaintext_profile(_ALPHA, '2' * 12, 'Admin'),
            'zeta-x': _plaintext_profile(_ZETA, '3' * 12, 'Admin'),
        },
    )
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: False)  # off a TTY so the current name isn't ANSI-wrapped
    cli.cmd_ls(full_config, 'alpha-current', False)
    lines = capsys.readouterr().out.splitlines()

    current_row = next(line for line in lines if 'alpha-current' in line and 'AWS_PROFILE' not in line)
    other_row = next(line for line in lines if 'alpha-other' in line)
    cross_session_row = next(line for line in lines if 'zeta-x' in line)
    # with the marker column gone, every name starts at one fixed offset — the current row is not shifted by a marker,
    # and the offset is stable across session breaks
    offsets = {
        current_row.index('alpha-current'),
        other_row.index('alpha-other'),
        cross_session_row.index('zeta-x'),
    }
    assert len(offsets) == 1
    assert all(cli._CURRENT not in row for row in (current_row, other_row, cross_session_row))


def _footer(out: str) -> str:
    return next(line for line in out.splitlines() if 'AWS_PROFILE' in line)


def test_footer_names_current_profile_and_reuses_its_row_data_when_known(env, monkeypatch, capsys):
    full_config = _full_config({_ALPHA: 'us-east-1'}, {'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'AdminAccess')})
    _expiry_file(_plaintext_cache_path(env, _ALPHA), hours=5)  # future -> live
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: False)
    cli.cmd_ls(full_config, 'alpha-a', False)
    footer = _footer(capsys.readouterr().out)

    assert 'AWS_PROFILE → alpha-a' in footer
    assert cli._CHECK in footer and 'live' in footer  # status glyph + word coloured by the session state
    assert '1' * 12 in footer and 'AdminAccess' in footer and 'us-east-1' in footer  # account / role  region
    assert cli._CURRENT in footer  # the orange current glyph leads the line
    assert 'no such profile' not in footer


def test_footer_names_current_profile_in_orange_on_tty(env, monkeypatch, capsys):
    full_config = _full_config({_ALPHA: 'us-east-1'}, {'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'Admin')})
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: True)
    cli.cmd_ls(full_config, 'alpha-a', False)
    footer = _footer(capsys.readouterr().out)

    assert f'{cli._ORANGE}alpha-a{cli._RESET}' in footer  # footer names the same profile the table highlights, orange
    assert f'{cli._ORANGE}{cli._CURRENT}{cli._RESET}' in footer  # orange current glyph leads the footer


def test_footer_warns_when_current_profile_is_not_in_config(env, monkeypatch, capsys):
    full_config = _full_config({_ALPHA: 'us-east-1'}, {'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'Admin')})
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: False)
    cli.cmd_ls(full_config, 'ghost', False)
    footer = _footer(capsys.readouterr().out)

    assert 'AWS_PROFILE → ghost' in footer
    assert 'no such profile in ~/.aws/config' in footer


def test_footer_when_aws_profile_unset(env, capsys):
    full_config = _full_config({_ALPHA: 'us-east-1'}, {'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'Admin')})
    cli.cmd_ls(full_config, None, False)  # None == $AWS_PROFILE unset (distinct from set to 'default')
    footer = _footer(capsys.readouterr().out)

    assert 'AWS_PROFILE not set' in footer
    assert 'export AWS_PROFILE=<profile> to pick one' in footer


def test_footer_is_the_last_content_line_then_a_final_blank(env, capsys):
    full_config = _full_config({_ALPHA: 'us-east-1'}, {'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'Admin')})
    cli.cmd_ls(full_config, 'alpha-a', False)
    lines = capsys.readouterr().out.split('\n')

    # net shape: ...last profile row / blank / footer / blank
    assert lines[-1] == '' and lines[-2] == ''  # a final blank line closes the block after the footer
    assert 'AWS_PROFILE' in lines[-3]  # the footer is the last non-blank line
    assert lines[-4] == ''  # the group-closing blank still sits between the last profile row and the footer


def test_countdown_hours_and_minutes():
    expiry = datetime.now(UTC) + timedelta(hours=2, minutes=5, seconds=30)
    assert cli._countdown(expiry) == '2h05m'


def test_countdown_minutes_only():
    expiry = datetime.now(UTC) + timedelta(minutes=45, seconds=30)
    assert cli._countdown(expiry) == '45m'


def test_countdown_expired_shows_negative_sign():
    expiry = datetime.now(UTC) - timedelta(hours=3, minutes=20, seconds=30)
    assert cli._countdown(expiry) == '-3h20m'


def test_status_detail_gone_ignores_expiry():
    # the state word now lives in the status column, so the colspan carries only the token note
    expiry = datetime.now(UTC) + timedelta(hours=1)
    assert cli._status_detail('gone', expiry) == 'no valid token'
    assert cli._status_detail('gone', None) == 'no valid token'


def test_status_detail_empty_when_no_expiry():
    assert cli._status_detail('plain', None) == ''


def test_status_detail_future_expiry_says_expires():
    expiry = datetime.now(UTC) + timedelta(hours=2, minutes=5, seconds=30)
    detail = cli._status_detail('live', expiry)
    assert detail.startswith('expires ')  # no duplicated state word ahead of the verb
    assert detail.endswith('(2h05m)')


def test_status_detail_past_expiry_says_expired():
    expiry = datetime.now(UTC) - timedelta(hours=3, minutes=20, seconds=30)
    detail = cli._status_detail('idle', expiry)
    assert detail.startswith('expired ')
    assert detail.endswith('(-3h20m)')


def test_ls_raises_without_sso_sessions(env):
    full_config = _full_config({}, {})
    with pytest.raises(SystemExit, match='no sso-sessions configured'):
        cli.cmd_ls(full_config, 'none', False)


def test_ls_output_has_no_ansi_when_not_a_tty(env, monkeypatch, capsys):
    full_config = _full_config({_ALPHA: 'us-east-1'}, {'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'Admin')})
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: False)
    cli.cmd_ls(full_config, 'none', False)
    assert '\033[' not in capsys.readouterr().out


def test_ls_output_has_ansi_when_a_tty(env, monkeypatch, capsys):
    full_config = _full_config({_ALPHA: 'us-east-1'}, {'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'Admin')})
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: True)
    cli.cmd_ls(full_config, 'none', False)
    assert '\033[' in capsys.readouterr().out


def test_ls_rule_under_header_spans_table_width_plain_off_tty(env, monkeypatch, capsys):
    full_config = _full_config({_ALPHA: 'us-east-1'}, {'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'Admin')})
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: False)
    cli.cmd_ls(full_config, 'none', False)
    lines = capsys.readouterr().out.splitlines()

    rule = lines[2]  # directly under the header row
    assert set(rule.strip()) == {'─'}  # a solid box-drawing rule
    assert rule.startswith('   ')  # hangs off the same left indent as the header
    assert len(rule) == len(lines[1])  # spans the full table width — matches the header row's width
    assert '\033[' not in rule  # plain, no dim, off a TTY


def test_ls_rule_is_dim_on_a_tty(env, monkeypatch, capsys):
    full_config = _full_config({_ALPHA: 'us-east-1'}, {'alpha-a': _plaintext_profile(_ALPHA, '1' * 12, 'Admin')})
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: True)
    cli.cmd_ls(full_config, 'none', False)
    rule = capsys.readouterr().out.splitlines()[2]

    assert rule.startswith(f'{cli._DIM}   ') and rule.endswith(cli._RESET)  # dim-wrapped rule
    assert '─' in rule

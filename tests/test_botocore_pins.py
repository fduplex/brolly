"""Behavioural pins on the botocore internals brolly mirrors, exercised against the botocore actually installed.

brolly re-implements three pieces of somebody else's code, because in each case it has to agree with a parser or a
consumer it does not own:

* ``_header_profile`` / ``_option_name`` re-implement how botocore reads ``~/.aws/config``, so that a surgical line
  edit removes exactly the keys botocore would have read;
* the token blob ``_device_login`` writes has to satisfy botocore's ``SSOTokenProvider`` or the session cannot renew
  itself silently;
* ``_registration_cache_key`` reproduces the AWS CLI v2's naming for the OIDC client registration it leaves behind.

Those mirrors were verified by hand once, by reading botocore's sources. This module is that audit turned into CI:
every test here drives the *real* installed botocore and asserts brolly still agrees with it, so a dependency bump
that changes the parser or the refresh contract fails a test instead of silently reintroducing divergence. Nothing
here asserts a version number — a botocore that changed behaviour without changing brolly's is the thing to catch,
whichever way its version moved.

Everything runs offline: config files live under ``tmp_path``, the sso-oidc client is a botocore ``Stubber``, and no
test reads or writes a real ``~/.aws``.
"""

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha1
from pathlib import Path
from typing import Any

import botocore.session
import pytest
from botocore import UNSIGNED
from botocore.config import Config
from botocore.configloader import load_config
from botocore.stub import Stubber
from botocore.tokens import SSOTokenProvider

from brolly import keychain

_SESSION = 'corp'
_PROFILE = 'corp-prod'
_START_URL = 'https://corp.awsapps.com/start'
_REGION = 'us-east-1'


@pytest.fixture(autouse=True)
def _isolate_aws(tmp_path, monkeypatch):
    """No test here may see the real ~/.aws — it holds live tokens, and the SSO cache paths are home-relative."""
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('AWS_CONFIG_FILE', str(tmp_path / 'config'))
    monkeypatch.delenv('AWS_PROFILE', raising=False)


@pytest.fixture
def aws_env(tmp_path) -> Path:
    return tmp_path / 'config'


# --- the ~/.aws/config parsing mirror ------------------------------------------------------------


def _mirror_profiles(text: str) -> dict[str, set[str]]:
    """What ``_config_remove_keys`` resolves a config file to: its own line loop, driving its own two helpers.

    The walk is copied rather than called because ``_config_remove_keys`` returns nothing — it rewrites the file.
    What is under test is the resolution it does on the way, so the resolution is what is reproduced here.
    """
    profiles: dict[str, set[str]] = {}
    section: str | None = None
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith('['):
            section = keychain._header_profile(stripped)
            if section is not None:
                profiles.setdefault(section, set())
        elif section is not None:
            option = keychain._option_name(line)
            if option is not None:
                profiles[section].add(option)
    return profiles


def _botocore_profiles(path: Path) -> dict[str, set[str]]:
    """The same file as the installed botocore resolves it — its real loader, not a re-reading of its rules."""
    return {profile: set(options) for profile, options in load_config(str(path))['profiles'].items()}


_CONFIG_FORMS = [
    pytest.param('[profile x]\nsso_session = corp\nsso_account_id = 111\n', id='plain'),
    pytest.param('[profile  x]\nsso_session = corp\nsso_account_id = 111\n', id='doubled-space-in-header'),
    pytest.param('[profile x ]\nsso_session = corp\nsso_account_id = 111\n', id='trailing-space-in-header'),
    pytest.param('  [profile x]\nsso_account_id = 111\n', id='indented-header'),
    pytest.param('[profile x] # a note\nsso_account_id = 111\n', id='hash-comment-after-header'),
    pytest.param('[profile x] ; a note\nsso_account_id = 111\n', id='semicolon-comment-after-header'),
    pytest.param('[profile "my prof"]\nsso_account_id = 111\n', id='quoted-name'),
    pytest.param('[profile\tx]\nsso_account_id = 111\n', id='tab-separated-header'),
    pytest.param('[profile x]y]\nsso_account_id = 111\n', id='second-bracket-in-header'),
    pytest.param('[default]\nsso_account_id = 111\n', id='default'),
    pytest.param('[profilex x]\nsso_account_id = 111\n', id='profile-prefixed-word'),
    pytest.param('[ profile x]\nsso_account_id = 111\n', id='padded-header-is-not-a-profile'),
    pytest.param('[ default ]\nsso_account_id = 111\n', id='padded-default-is-not-a-profile'),
    pytest.param('[profilex]\nsso_account_id = 111\n', id='no-separator-is-not-a-profile'),
    pytest.param('[profile x y]\nsso_account_id = 111\n', id='three-word-header-is-not-a-profile'),
    pytest.param('[profile x]\nsso_account_id: 111\nsso_role_name:ReadOnly\n', id='colon-delimited-options'),
    pytest.param('[profile x]\nSSO_Account_ID = 111\nSso_Role_Name = R\n', id='mixed-case-option-names'),
    pytest.param('[profile x]\n  sso_account_id = 111\nsso_role_name = R\n', id='indented-first-option'),
    pytest.param('[profile x]\n\tsso_account_id = 111\n', id='tab-indented-first-option'),
    pytest.param('[profile x]\nsso_account_id=111\n', id='no-space-around-delimiter'),
    pytest.param('[profile x]\nsso_account_id  =  111\n', id='padded-option-name'),
    pytest.param(f'[profile x]\nsso_start_url = {_START_URL}\n', id='colon-inside-an-equals-value'),
    pytest.param('[profile x]\nfoo: a=b\n', id='equals-inside-a-colon-value'),
    pytest.param('[profile x]\nsso_account_id =\n', id='blanked-value'),
    pytest.param('[profile x]\n# a note\n; another note\nsso_account_id = 111\n', id='full-line-comments'),
    pytest.param('[profile x]\n\n\nsso_account_id = 111\n\n', id='blank-lines'),
    pytest.param('[sso-session corp]\nsso_region = us-east-1\n\n[profile x]\nsso_account_id = 1\n', id='sso-session'),
    pytest.param('[profile a]\nsso_account_id = 1\n\n[profile b]\nsso_account_id = 2\n', id='two-profiles'),
]

_MIRROR_OVERREACH_FORMS = [
    pytest.param('[profile x]\nsso_session = corp\n  sso_account_id = 111\n', id='indented-continuation-line'),
    pytest.param('[profile x]\n# sso_account_id = 111\nsso_role_name = R\n', id='commented-out-option'),
]


@pytest.mark.parametrize('text', _CONFIG_FORMS)
def test_the_config_mirror_resolves_a_config_file_exactly_as_the_installed_botocore_does(text, aws_env):
    """Header forms and option spellings botocore accepts, resolved twice — once by botocore, once by the mirror.

    The pair has to be exact in both directions. A profile the mirror does not resolve is a section a conversion
    walks past, leaving `sso_account_id`/`sso_role_name` behind while brolly reports the profile secured and deletes
    its token blob: the SSO credential provider goes on vending plaintext credentials from a profile that is
    supposedly locked. A profile the mirror resolves and botocore does not is the opposite failure — brolly editing
    a section of the user's config it was never asked to touch.
    """
    aws_env.write_text(text)
    assert _mirror_profiles(text) == _botocore_profiles(aws_env)


@pytest.mark.parametrize('text', _CONFIG_FORMS + _MIRROR_OVERREACH_FORMS)
def test_the_config_mirror_never_misses_a_profile_or_an_option_the_installed_botocore_reads(text, aws_env):
    """The one-directional half of the same parity, over forms where the mirror is deliberately the wider net.

    A continuation line and a commented-out key are both read by the mirror as options and by botocore as part of
    something else, so exact parity does not hold for them — but the containment that matters does, and it is the
    only direction with a security consequence. Over-reaching costs a line the user wrote; under-reaching leaves a
    live credential trigger in a profile brolly has called secure.
    """
    aws_env.write_text(text)
    mirror, botocore_view = _mirror_profiles(text), _botocore_profiles(aws_env)
    assert set(botocore_view) == set(mirror)
    for profile, options in botocore_view.items():
        assert options <= mirror[profile]


# --- the token blob SSOTokenProvider consumes ----------------------------------------------------


def _write_sso_config(path: Path) -> None:
    path.write_text(
        f'[sso-session {_SESSION}]\n'
        f'sso_start_url = {_START_URL}\n'
        f'sso_region = {_REGION}\n'
        f'\n'
        f'[profile {_PROFILE}]\n'
        f'sso_session = {_SESSION}\n'
    )


def _brolly_blob() -> dict[str, str]:
    """A token blob shaped exactly as ``keychain._device_login`` writes one — same keys, same order, same types.

    ``expiresAt`` sits inside botocore's 15-minute refresh window but is not yet past, which is what makes every
    test below deterministic without freezing the clock: the provider always tries to refresh, and when it declines
    it still has a usable token to hand back rather than raising on an expired one.
    """
    now = datetime.now(UTC)
    return {
        'startUrl': _START_URL,
        'region': _REGION,
        'accessToken': 'stale-access-token',
        'expiresAt': (now + timedelta(minutes=10)).isoformat(),
        'clientId': 'brolly-client-id',
        'clientSecret': 'brolly-client-secret',
        'registrationExpiresAt': (now + timedelta(days=80)).isoformat(),
        'refreshToken': 'brolly-refresh-token',
    }


class _UnusableOidc:
    """An sso-oidc client that fails the test if botocore reaches for it — these cases must not call out at all."""

    def create_token(self, **kwargs: object) -> dict[str, object]:
        raise AssertionError(f'refresh attempted with {sorted(kwargs)}')


def _provider(cache: dict[str, dict[str, str]], client: Any) -> SSOTokenProvider:
    """A real ``SSOTokenProvider`` over a real botocore session, with the sso-oidc client injected.

    ``_client`` is a ``CachedProperty``, so seeding it is exactly the caching the provider would have done itself —
    everything else about the provider, including how it resolves the sso-session out of ~/.aws/config, is real.
    """
    provider = SSOTokenProvider(botocore.session.Session(profile=_PROFILE), cache=cache, profile_name=_PROFILE)
    provider._client = client
    return provider


_REFRESH_REQUIRED_KEYS = ['refreshToken', 'clientId', 'clientSecret', 'registrationExpiresAt']


def test_a_brolly_shaped_token_blob_still_satisfies_the_installed_sso_token_provider(aws_env):
    """The blob brolly writes into the keychain drives a silent refresh through the real provider.

    Three couplings at once. The blob is found at all only because ``keychain._cache_key`` derives the same name
    botocore's ``SSOTokenLoader`` looks under — a mismatch raises out of the mandatory refresh rather than passing
    quietly. The stubbed ``create_token`` is checked against the real sso-oidc model *and* against the exact
    parameters the provider is expected to build out of the blob. And the blob botocore then writes back carries the
    same keys brolly's own writer does, so a refreshed session stays refreshable.
    """
    _write_sso_config(aws_env)
    cache = {keychain._cache_key(_SESSION): _brolly_blob()}
    session = botocore.session.Session(profile=_PROFILE)
    client = session.create_client('sso-oidc', region_name=_REGION, config=Config(signature_version=UNSIGNED))
    stubber = Stubber(client)
    stubber.add_response(
        'create_token',
        {
            'accessToken': 'fresh-access-token',
            'refreshToken': 'next-refresh-token',
            'tokenType': 'Bearer',
            'expiresIn': 28800,
        },
        {
            'grantType': 'refresh_token',
            'clientId': 'brolly-client-id',
            'clientSecret': 'brolly-client-secret',
            'refreshToken': 'brolly-refresh-token',
        },
    )

    with stubber:
        frozen = _provider(cache, client).load_token().get_frozen_token()

    stubber.assert_no_pending_responses()
    assert frozen.token == 'fresh-access-token'
    assert set(cache[keychain._cache_key(_SESSION)]) == set(_brolly_blob())


@pytest.mark.parametrize('missing', _REFRESH_REQUIRED_KEYS)
def test_dropping_any_field_the_installed_provider_requires_stops_the_refresh(missing, aws_env):
    """The other side of the coupling: each of these four keys is load-bearing, so brolly writing all four is not
    belt-and-braces. Drop one and botocore declines to refresh — silently, handing back the stale token — which for
    brolly means the session dies at its next expiry and the user is sent back to a browser."""
    _write_sso_config(aws_env)
    blob = {key: value for key, value in _brolly_blob().items() if key != missing}
    cache = {keychain._cache_key(_SESSION): dict(blob)}

    frozen = _provider(cache, _UnusableOidc()).load_token().get_frozen_token()

    assert frozen.token == 'stale-access-token'
    assert cache[keychain._cache_key(_SESSION)] == blob


def test_an_expired_client_registration_stops_the_refresh(aws_env):
    """``registrationExpiresAt`` is not merely required to be present — the provider reads it, and a registration
    past its ~90-day life ends the session's silent renewal even with a live refresh token in hand."""
    _write_sso_config(aws_env)
    blob = _brolly_blob() | {'registrationExpiresAt': (datetime.now(UTC) - timedelta(days=1)).isoformat()}
    cache = {keychain._cache_key(_SESSION): dict(blob)}

    frozen = _provider(cache, _UnusableOidc()).load_token().get_frozen_token()

    assert frozen.token == 'stale-access-token'
    assert cache[keychain._cache_key(_SESSION)] == blob


# --- the AWS CLI's registration cache-key derivation ---------------------------------------------

# Pinned against fixtures rather than against the code it mirrors: the AWS CLI v2 is not an installable dependency
# here, so unlike the two couplings above there is nothing live to exercise. Each digest below was computed by
# following the algorithm quoted in ``_registration_cache_key``'s own docstring, by hand, not by calling brolly.
# The limitation is worth stating plainly: this catches a regression on brolly's side and nothing else. Drift on the
# AWS CLI's side stays invisible to CI and is only ever found by re-auditing awscli when the CLI is upgraded.

_REGISTRATION_KEY_FIXTURES: dict[str, tuple[str, dict[str, str], str]] = {
    'no-registration-scopes': (_SESSION, {}, '5fdb0c628fe4a3a78887b40232874154e433f9a4'),
    'one-scope': (
        _SESSION,
        {'sso_registration_scopes': 'sso:account:access'},
        '1b56c55d6e723362537167a7f43960b8185b5a80',
    ),
    'two-scopes-with-padding': (
        _SESSION,
        {'sso_registration_scopes': ' sso:account:access , codewhisperer:completions '},
        'd0c66e261efcffc5485082e2535b941f0eef5e81',
    ),
    'empty-scopes': (_SESSION, {'sso_registration_scopes': ''}, '9c9e954cf1577eb29509a1d8ce6f97181d8afeeb'),
    'only-separators': (_SESSION, {'sso_registration_scopes': ' , , '}, '9c9e954cf1577eb29509a1d8ce6f97181d8afeeb'),
    'other-region': (_SESSION, {'sso_region': 'eu-west-1'}, 'a5ef4a75f83137c047e4ff336d1dade82162017b'),
    'other-start-url': (
        _SESSION,
        {'sso_start_url': 'https://other.awsapps.com/start'},
        '5646eed145a38a691202df0b8696d5ee14c26607',
    ),
    'other-session-name': ('other-corp', {}, '6a9179e6ad38192ae4328ce6c7cc4712931158e8'),
}


@pytest.mark.parametrize(
    'session_name, overrides, expected', _REGISTRATION_KEY_FIXTURES.values(), ids=list(_REGISTRATION_KEY_FIXTURES)
)
def test_the_registration_cache_key_matches_the_aws_cli_derivation(session_name, overrides, expected):
    """Fixed digests, so the five inputs, their JSON encoding and the scope parsing are all pinned at once.

    ``sso_registration_scopes`` absent means ``None`` and an empty one means ``[]``; those are different JSON and so
    different file names, which is why both are here. Getting any of it wrong yields a name that matches nothing in
    ~/.aws/sso/cache — a purge that silently leaves the OIDC client registration `aws sso login` cached behind.
    """
    sso_config = {'sso_start_url': _START_URL, 'sso_region': _REGION} | overrides
    assert keychain._registration_cache_key(session_name, sso_config) == expected


@pytest.mark.parametrize('missing', ['sso_start_url', 'sso_region'])
def test_the_registration_cache_key_is_unknowable_without_the_sso_session_block(missing):
    """Half the inputs come from config brolly may not have been handed, and a guessed name would name a file
    belonging to somebody else. No inputs, no key — the caller falls back to the token blob's own clientId."""
    sso_config = {'sso_start_url': _START_URL, 'sso_region': _REGION}
    del sso_config[missing]
    assert keychain._registration_cache_key(_SESSION, sso_config) is None


def test_the_registration_cache_key_fixtures_agree_with_the_documented_algorithm():
    """The fixtures re-derived from the algorithm as ``_registration_cache_key``'s docstring quotes it, so a reader
    can see where the digests above came from without running the AWS CLI — and so a typo in one is caught."""
    for session_name, overrides, expected in _REGISTRATION_KEY_FIXTURES.values():
        sso_config = {'sso_start_url': _START_URL, 'sso_region': _REGION} | overrides
        raw_scopes = sso_config.get('sso_registration_scopes')
        args = {
            'tool': 'botocore',
            'startUrl': sso_config['sso_start_url'],
            'region': sso_config['sso_region'],
            'scopes': None if raw_scopes is None else [s.strip() for s in raw_scopes.split(',') if s.strip()],
            'session_name': session_name,
        }
        assert sha1(json.dumps(args, sort_keys=True).encode('utf-8')).hexdigest() == expected

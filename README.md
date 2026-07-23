# brolly

> *brolly* — British informal for umbrella. One login covers every profile under an AWS SSO session.

[![PyPI version](https://img.shields.io/pypi/v/brolly)](https://pypi.org/project/brolly/)
[![Python versions](https://img.shields.io/pypi/pyversions/brolly)](https://pypi.org/project/brolly/)
[![CI](https://github.com/fduplex/brolly/actions/workflows/ci.yml/badge.svg)](https://github.com/fduplex/brolly/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](LICENSE)

A small, pure-Python CLI for AWS IAM Identity Center (SSO): log in once per session, switch accounts and roles
in place, and keep your profiles fresh — without ever touching `$AWS_PROFILE`.

brolly drives AWS SSO the way the modern `[sso-session]` config was meant to be used: authenticate once against
a session and every profile that references it is usable. It refreshes and verifies credentials cheaply (the
default), forces a fresh login when you want one, repoints the current profile to a different account/role, or
adds a new profile under an existing session — and it ships a freshness-aware shell-prompt pill so you can see
your credential state at a glance.

```
brolly                                  verify/refresh the current profile (same as `brolly refresh`)
brolly login [-s <session>]             force a fresh device-code login for a session
brolly switch                           repoint the current profile's account/role
brolly refresh [<profile>] [-s <session>]
brolly add <profile> [-s <session>]
```

## Install

```console
$ uv tool install brolly      # recommended
$ pipx install brolly
$ pip install brolly
```

**Prerequisites:**

- **AWS CLI v2** on your `$PATH`. brolly shells out to `aws sso login` and `aws configure set`; everything else
  (listing accounts/roles, resolving tokens) goes through boto3. The AWS CLI is *not* a pip dependency — install
  it separately: <https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html>.
- **Python 3.14+**.
- **A Unix-like terminal.** The arrow-key picker uses `termios`/`tty`, so brolly's interactive menus need a
  POSIX TTY (Linux, macOS, WSL). Off a TTY it falls back to numeric selection.

## Mental model

Modern AWS SSO config in `~/.aws/config` has two layers:

- **`[sso-session <name>]`** — the session. Holds `sso_start_url`, `sso_region`, etc. Logging in against
  a session caches ONE token, keyed by SHA1 of the session name (`~/.aws/sso/cache/<sha1>.json`).
- **`[profile <name>]`** — a profile references a session via `sso_session = <name>` and adds its own
  `sso_account_id` / `sso_role_name`. Any number of profiles can point at the same session.

Because the token is cached per-session, not per-profile, **every profile under the same session shares one
login** — authenticate once and all sibling profiles are usable. (One login covering many profiles is where the
name comes from.)

`$AWS_PROFILE` is a fixed handle you set yourself in each shell. **brolly never touches it** — it only changes
what a profile resolves to (`switch`), creates new profiles (`add`), or verifies a profile's credentials
(`refresh`, which targets the `aws` CLI with `--profile` rather than mutating the ambient env). To actually use
a different profile you still `export AWS_PROFILE=<name>` yourself. There is no shell wrapper and nothing that
rewrites your environment behind your back.

## Commands

### `brolly`

Bare `brolly` (no subcommand) is shorthand for `brolly refresh` on the current `$AWS_PROFILE` — cheap, no
browser unless the session is actually dead.

```console
$ brolly
✔  corp-dev live → arn:aws:sts::111111111111:assumed-role/AdministratorAccess/alex
```

### `brolly login`

Forces a fresh device-code login for an sso-session, unconditionally — no token check first. Session
defaults to the current `$AWS_PROFILE`'s `sso_session`; `-s/--session` targets a different session. It's
session-scoped, not profile-scoped (no profile argument).

This is the rare escape hatch for "I'm still valid but I want a new login anyway" — `refresh` (and therefore
bare `brolly`) already logs in automatically whenever a session is actually dead, so day to day you shouldn't
need this.

```console
$ brolly login
$ brolly login -s corp
```

### `brolly switch`

Interactively repoints the CURRENT `$AWS_PROFILE` to a different account/role under its own session. Arrow-key
picker (`↑`/`↓` or `j`/`k`, `enter` to select, `q`/`esc`/Ctrl-C to quit); shows the account list, then the role
list (skipped if the account has exactly one role). Current account/role are pre-selected. `sso_account_id`,
`sso_role_name`, and `sso_account_name` of that profile are rewritten in place — everything else about the
profile is untouched. Recording `sso_account_name` is what lets the shell prompt show a friendly account name
instead of the raw ID.

```console
$ export AWS_PROFILE=corp-prod
$ brolly switch
  select account   ↑/↓ move · enter select · q quit
      ACCOUNT       NAME
      111111111111  corp-prod       ← current
    ▶ 222222222222  corp-staging

  select role   ↑/↓ move · enter select · q quit
      ROLE
    ▶ AdministratorAccess

✔  corp-prod → 222222222222 (corp-staging) / AdministratorAccess
```

### `brolly refresh`

The cheap, no-browser daily-driver check. Takes an optional `<profile>` positional (default: `$AWS_PROFILE`)
and an optional `-s/--session <name>` that asserts which sso-session you're operating in (default: the
`sso_session` of the current `$AWS_PROFILE`). The target profile must actually belong to the asserted session,
or the command fails loudly — this makes crossing sessions always deliberate:

```console
$ AWS_PROFILE=corp-dev brolly refresh corp-prod
✔  corp-prod live → arn:aws:sts::222222222222:assumed-role/AdministratorAccess/alex

$ AWS_PROFILE=customer-admin brolly refresh corp-prod
profile 'corp-prod' is under session 'corp', not 'customer' — use -s corp to target it

$ AWS_PROFILE=customer-admin brolly refresh corp-prod -s corp
✔  corp-prod live → arn:aws:sts::222222222222:assumed-role/AdministratorAccess/alex
```

None of this ever touches `$AWS_PROFILE`: `refresh` runs `aws sts get-caller-identity --profile <target>` —
overriding the ambient env var for just that one call — and logs in with `--sso-session <session>` if needed.
Your shell's `$AWS_PROFILE` is exactly what it was before; that's the whole point of `-s` — it lets you check on
(or log into) a profile in another session without poisoning your shell.

Under the hood: `get-caller-identity` forces credential resolution and lets botocore refresh the hourly SSO
token as a side effect — but only when the token is already lapsed or within ~15 min of expiry (botocore's own
refresh window). If it still has plenty of time left, `refresh` just confirms you're authenticated without
resetting the clock — that's the intended cheap behavior. Contrast with `brolly login`, which always does a full
`aws sso login` unconditionally.

If credentials can't be resolved at all (the 7-day session is dead), it prints a notice, falls through to a
device-code `aws sso login`, and retries. It also opportunistically backfills `sso_account_name` on the target
profile if that key is missing (one `list_accounts` call, made only when absent) — so an existing profile's
prompt name heals itself the first time you refresh it.

### `brolly add <profile> [-s <session>]`

Creates a NEW profile under an existing sso-session, walks the same account/role picker, and leaves it
authenticated and ready to use. `-s/--session` picks the session (default: the `sso_session` of the current
`$AWS_PROFILE`) — there's no cross-session guard here like `refresh` has, since the profile being written is
new:

```console
$ brolly add corp-qa                     # session inferred from current $AWS_PROFILE's sso_session
$ brolly add customer-admin -s customer  # explicit session
```

What it does:

1. Refuses if `<profile>` already exists (tells you to use `brolly switch` instead), or if `<session>` isn't a
   known `sso-session` (lists the available ones).
2. Writes a profile skeleton: `sso_session = <session>`, plus `region`/`output` copied from a sibling profile on
   the same session if one exists, otherwise the session's `sso_region` and `json`.
3. Ensures a valid token for the session, logging in if needed.
4. Runs the account/role picker, then writes `sso_account_id` / `sso_role_name` / `sso_account_name`.

It does **not** change `$AWS_PROFILE`. To use the new profile: `export AWS_PROFILE=<name>`.

**Recovery:** if you Ctrl-C out of the picker mid-`add`, the profile skeleton (step 2) is already written to
`~/.aws/config`, so re-running `brolly add` will hit the "already exists" guard. Finish it instead:

```console
$ export AWS_PROFILE=new-account
$ brolly switch          # or `brolly` first if the token also expired
```

### Common tasks

| Situation | Command |
|---|---|
| Verify/refresh current creds | `brolly` |
| Force a fresh login (session healthy but you want a new one) | `brolly login` |
| Wrong account or role for the current profile | `brolly switch` |
| Need a new profile under the current session | `brolly add <name>` then `export AWS_PROFILE=<name>` |
| Need a new profile under a different session, e.g. `customer` | `brolly add <name> -s customer` |
| Refresh a profile in a different session from this shell | `brolly refresh <profile> -s <session>` |
| Interrupted a `brolly add` mid-picker | `export AWS_PROFILE=<name>` then `brolly switch` |

## Shell prompt integration

brolly ships a drop-in `__aws_ps1` function for your `~/.bashrc` that renders a colored `AWS_PROFILE` pill
reflecting the **local, filesystem-only** state of the session token — no network call, no `aws`/boto3
invocation on every prompt:

- **live** (bright orange) — hourly token still valid.
- **idle** (grey, clock glyph) — cached but lapsed; refreshes automatically on next use.
- **gone** (red, cross glyph) — no cached token; run `brolly`.
- **plain** (neutral grey) — profile has no `sso_session` (not an SSO profile).

A dead 7-day session can't be detected locally, so it still reads as `idle` rather than `gone`. The pill also
shows the account: `<profile> · <account>`, where `<account>` is the friendly `sso_account_name` when the
profile has one, falling back to the raw `sso_account_id` if not. Names get populated by `switch`, `add`, and
`refresh`; until one of those runs against a given profile, the pill just falls back to the raw account ID.

Drop this into your `~/.bashrc` and add `$(__aws_ps1)` to your `PS1`. It needs a **[Nerd Font](https://www.nerdfonts.com/)**
for the powerline separators and glyphs.

```bash
__aws_ps1() {
  [[ -z $AWS_PROFILE ]] && return

  # Cheap, filesystem-only freshness check — no aws/boto3 call, no network.
  # live = hourly token still valid · idle = cached but lapsed (refreshes on next use) · gone = no token, must log in.
  # The 7-day session's true death can't be known locally, so a dead session reads as "idle", not "gone".
  local cfg="${AWS_CONFIG_FILE:-$HOME/.aws/config}"
  local session acct cache exp now state sbg sfg glyph
  IFS=$'\t' read -r session acct < <(awk -v h="[profile $AWS_PROFILE]" '
    $0==h {i=1; next}
    /^\[/ {i=0}
    i && /^[[:space:]]*sso_session[[:space:]]*=/      {v=$0; sub(/^[^=]*=[[:space:]]*/,"",v); s=v}
    i && /^[[:space:]]*sso_account_name[[:space:]]*=/ {v=$0; sub(/^[^=]*=[[:space:]]*/,"",v); n=v}
    i && /^[[:space:]]*sso_account_id[[:space:]]*=/   {v=$0; sub(/^[^=]*=[[:space:]]*/,"",v); a=v}
    END {print s "\t" (n!=""?n:a)}' "$cfg" 2>/dev/null)

  if [[ -z $session ]]; then
    state=plain
  else
    cache="$HOME/.aws/sso/cache/$(printf %s "$session" | sha1sum | cut -c1-40).json"
    if [[ ! -f $cache ]]; then
      state=gone
    else
      exp=$(sed -n 's/.*"expiresAt"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$cache" | head -1)
      printf -v now '%(%s)T' -1
      exp=$(date -d "$exp" +%s 2>/dev/null)
      [[ -n $exp && $exp -gt $now ]] && state=live || state=idle
    fi
  fi

  case $state in
    live)  sbg=214 sfg=236 glyph='' ;;         # bright AWS orange — creds are live
    idle)  sbg=240 sfg=214 glyph=$' ' ;; #  grey clock — lapsed, will refresh on next use
    gone)  sbg=160 sfg=231 glyph=$' ' ;; #  red cross — no cached token, run brolly
    plain) sbg=238 sfg=250 glyph='' ;;         # non-SSO profile — neutral
  esac

  # powerline pill:  amazon-glyph | profile ; \001/\002 wrap non-printing bytes for correct prompt-width math
  local E=$'\033' A=$'\001' B=$'\002' PL=$'' AWS=$''
  printf '%s%s%s%s%s' \
    "${A}${E}[48;5;238;38;5;214;1m${B} ${AWS} " \
    "${A}${E}[38;5;238;48;5;${sbg}m${B}${PL}" \
    "${A}${E}[48;5;${sbg};38;5;${sfg};1m${B} ${glyph}${AWS_PROFILE}${acct:+ · $acct} " \
    "${A}${E}[0;38;5;${sbg}m${B}${PL}" \
    "${A}${E}[0m${B} "
}
```

## How it compares

No single existing tool combines what brolly does. Its niche is the *combination*: native to the `sso-session` block
+ in-place `switch`/`add` + never mutating `$AWS_PROFILE` + a shipped freshness-aware prompt pill +
pure-Python/pip.

- **[aws-sso-util](https://github.com/benkehoe/aws-sso-util)** (Ben Kehoe) is the closest sibling — pure-Python,
  config-native, and non-invasive, in the same spirit as brolly. But it has no prompt integration, no in-place
  single-profile repoint, and predates the `sso-session` block.
- **[granted](https://granted.dev/)** and **[aws-sso-cli](https://github.com/synfinatic/aws-sso-cli)** are
  excellent tools, but they're Go binaries that install a shell wrapper mutating your shell and generate bulk
  static profiles. brolly is deliberately thinner: no wrapper, no bulk generation, in-place edits only.
- **[awsume](https://awsu.me/)** targets classic IAM role assumption, not Identity Center.

This is positioning, not disparagement — if you want OS-keychain-encrypted tokens today, reach for aws-vault,
granted, or aws-sso-cli (see caveats below and the roadmap).

## Design notes & caveats

Two things to own up front:

- **`switch` rewrites `~/.aws/config` globally.** A profile lives in one shared config file, so switching the
  account/role of a profile name silently retargets *any other shell* pinned to the **same profile name** on its
  next command. Safe use = **one distinct profile name per concurrent context.** If you keep two shells on the
  same account simultaneously, give them different profile names. This is the one real footgun — stated plainly.
- **Tokens live in the stock plaintext `~/.aws/sso/cache/`** — the very same cache the `aws` CLI uses. brolly
  adds no encryption of its own; it's a thin layer over the stock cache by design. For OS-keychain encryption
  *today*, use aws-vault / granted / aws-sso-cli. Encrypted storage is the lead roadmap item below.

## Roadmap

1. **Keychain-backed token storage via a `credential_process` mode.** An opt-in mode where brolly does the
   device auth itself, stores the SSO token in the OS keychain (via the Python
   [`keyring`](https://github.com/jaraco/keyring) library), and registers itself as each profile's
   `credential_process` — so credentials never sit in plaintext on disk and SDK consumers stay fully transparent
   (just `AWS_PROFILE`, no shell wrapper). The prompt pill's freshness check would then read a small non-secret
   expiry sidecar instead of the plaintext cache. On headless Linux with no OS keychain, `keyring` falls back to
   an encrypted-file backend guarded by a passphrase. This mode makes brolly "take over credential resolution,"
   which is exactly the trade the plaintext default avoids — so it stays **opt-in**, keeping brolly a thin stock-
   cache layer by default.
2. Test suite, CI, and publish to the `fduplex` PyPI org.

## License

[Apache-2.0](LICENSE) © 2026 Full Duplex Media

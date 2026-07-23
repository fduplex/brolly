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
brolly secure enable|disable [-s <session>]   opt-in: keep a session's token in your OS keychain
```

## Install

```console
$ uv tool install brolly      # recommended
$ pipx install brolly
$ pip install brolly
```

Opt-in [secure mode](#secure-mode-os-keychain) (tokens in the OS keychain) is built in — no extra to install.

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
| Keep a session's token out of plaintext | `brolly secure enable -s <session>` |

## Secure mode (OS keychain)

By default brolly is a thin layer over the stock `~/.aws/sso/cache` — the same plaintext token cache the `aws`
CLI uses. **Secure mode** is an opt-in that moves the SSO token off disk and into your OS keychain (macOS
Keychain, GNOME Keyring / KWallet, or `pass` + gpg-agent on a desktop-less Linux box — see
[Choosing a backend](#choosing-a-backend)), then registers brolly as each profile's `credential_process` so every
SDK and the `aws` CLI keep working with nothing but `$AWS_PROFILE` — no shell wrapper, no plaintext token.

It's built in (the [`keyring`](https://github.com/jaraco/keyring) library ships as a dependency); it just needs a
keychain backend, which macOS and desktop Linux already have.

### `brolly secure enable [-s <session>]`

Logs the session in (a device-code login brolly runs itself, storing the token in your keychain) and rewrites
every profile under that session to use `credential_process`. Once the token is safely in the keychain it also
**deletes the now-redundant plaintext token** from `~/.aws/sso/cache/`, so nothing sensitive is left on disk.
Idempotent — re-run it after `brolly add` to pull new profiles into secure mode (and to clean up any leftover
plaintext token from a session you secured before this behavior existed).

```console
$ brolly secure enable -s corp

To authorize brolly for session 'corp', open:

    https://device.sso.us-east-1.amazonaws.com/?user_code=WXYZ-1234

and confirm the code: WXYZ-1234

✓ authorized — SSO token stored in your OS keychain
✓ removed plaintext token cache for session 'corp'
✓ secure mode on for session 'corp' — 3 profile(s) now use the OS keychain
```

Nothing else about your workflow changes: `export AWS_PROFILE=corp-prod` and every SDK resolves credentials
through brolly, which pulls the keychain token and vends short-lived role credentials on demand. `brolly`,
`brolly refresh`, and `brolly switch` all keep working and stay in secure mode.

### `brolly secure login [-s <session>]`

Re-authorizes a secured session, refreshing its keychain token in place. brolly normally refreshes silently
using the stored refresh token; reach for this only if the 7-day session has fully lapsed (bare `brolly` also
triggers it automatically when it finds a dead secured session).

### `brolly secure disable [-s <session>]`

Reverts every secured profile under the session back to a stock plaintext-cache SSO profile and deletes the
token from your keychain — a clean, complete undo of `enable`.

### How it works

- **The token** (with its refresh token) lives in the keychain under service `brolly-sso`, keyed the way botocore
  keys its own cache (SHA1 of the session name). brolly plugs a keychain-backed cache into botocore's token
  provider, so **silent hourly refresh still happens** — no reimplementation, just a different vault.
- **A secured profile** keeps `sso_session` (needed to refresh the token) but moves `sso_account_id` /
  `sso_role_name` under `brolly_sso_*` and adds `credential_process`. That combination deactivates botocore's
  built-in SSO credential provider so resolution flows through brolly — otherwise botocore would find the
  (now-absent) plaintext token and fail instead of falling through.
- **The prompt pill** reads a small non-secret expiry sidecar (`<aws-config-dir>/brolly/<sha1>.json`) instead of
  the plaintext cache, so it stays a cheap filesystem check — no keychain access, no secret on disk.
- **No environment variable to keep exported.** `secure enable` writes the chosen backend to
  `~/.aws/brolly/config.json` (alongside the sidecars), and every `credential-process` call re-selects it itself —
  so credential resolution works from any venv, a cron job, or an IDE without `PYTHON_KEYRING_BACKEND` set. (It
  does run the `brolly` command, so keep brolly on your `PATH`.)

### Choosing a backend

`keyring` needs a real backend, and the one that matters for `credential_process` is one that stays **unlocked
for your session** — because brolly's `credential-process` is spawned fresh and non-interactively on every cold
credential resolution, so it can't stop to prompt. macOS Keychain and desktop Linux's gnome-keyring / KWallet
already work that way (unlocked at login by a session daemon). If `keyring` can't find a backend, brolly says so
and stops rather than failing obscurely.

`secure enable` **auto-detects** the backend: it uses a real OS keychain if one is active, otherwise it falls back
to `pass` when its store is set up. So on most machines you don't name a backend at all — and whatever it picks is
saved to `~/.aws/brolly/config.json` and re-applied on every later call. Override with `--backend <dotted.path>`
when you want a specific one.

Backends live in **brolly's own environment** — because `credential_process` runs the `brolly` executable, which
uses brolly's venv, *not* the venv of whatever triggered the credential lookup. The `pass` backend
(`keyring_pass`) ships with brolly; other backends (e.g. 1Password) you install once alongside brolly
(`uv tool install brolly --with <pkg>`, or `pipx inject brolly <pkg>`).

**Linux without a desktop (no gnome-keyring / KWallet): use `pass` + gpg-agent.** This is the recommended path —
`pass` stores each secret gpg-encrypted, and gpg-agent is the session daemon that keeps your key unlocked, so
reads are silent once it's warm. (Encrypting a *write* needs no passphrase at all, so token refreshes never
prompt.) `keyring_pass` is bundled, so you only need the `pass` CLI itself and an initialized store — then
`secure enable` finds it automatically:

```console
$ sudo apt install pass                              # the pass CLI (system-wide)
$ pass init <your-gpg-key-id>                        # initialize the store (brolly then auto-detects it)
$ brolly secure enable -s corp                       # picks pass, saves it to ~/.aws/brolly/config.json
```

**Unlock gpg-agent once per session.** Because `credential-process` has no TTY, gpg-agent must already be warm
when it runs — a cold cache would fail. Two ways:

- Keep the agent unlocked all session by raising the cache TTL in `~/.gnupg/gpg-agent.conf`
  (`max-cache-ttl 34560000`), then do one `pass show` (or `brolly secure enable`) in a terminal at login; the
  first decrypt prompts once (pinentry-curses, no X11 needed) and the agent caches it.
- For zero-touch warming at login, preset the passphrase with `gpg-preset-passphrase` (add `allow-preset-passphrase`
  to `gpg-agent.conf`) — the same pattern used by
  [borg-backup](https://github.com/thevinchi/borg-backup)'s `borg-backup-passphrase`.

**1Password / other vaults.** Anything with a `keyring` backend works — install it into brolly's env and pass its
dotted path to `--backend`. For example `onepassword-keyring` with a 1Password service-account token
(`OP_SERVICE_ACCOUNT_TOKEN`) for non-interactive reads. Note the trade: without the desktop app there's no
biometric unlock, so you're trusting a long-lived service-account token in your environment.

**Encrypted-file fallback (last resort).** `keyrings.alt`'s `EncryptedKeyring` needs no daemon, but that's the
problem: it has nothing to keep it unlocked, so it prompts for the master passphrase in *every* new process —
meaning a prompt on roughly every `aws` call and a hard failure anywhere non-interactive. Only viable for
occasional interactive use; otherwise the plaintext-cache default is the more honest choice.

```console
$ uv tool install brolly --with keyrings.alt --with pycryptodome
$ brolly secure enable -s corp --backend keyrings.alt.file.EncryptedKeyring
```

See the [keyring docs](https://github.com/jaraco/keyring#using-keyring) for the full backend list.

## Shell prompt integration

`brolly ps1` renders a colored `AWS_PROFILE` pill for your prompt, reflecting the **local, filesystem-only** state
of the session token — no network call, no keychain access, no `aws`/boto3 invocation:

- **live** (bright orange) — token still valid.
- **idle** (grey, clock glyph) — cached but lapsed; refreshes automatically on next use.
- **gone** (red, cross glyph) — no cached token; run `brolly`.
- **plain** (neutral grey) — profile has no `sso_session` (not an SSO profile).

Add it to your `PS1`. It needs a **[Nerd Font](https://www.nerdfonts.com/)** for the powerline separators and
glyphs:

```bash
export PS1='$(brolly ps1)\u@\h:\w\$ '
```

It reads whichever store the profile actually uses — the non-secret expiry sidecar for
[secure-mode](#secure-mode-os-keychain) profiles, or the stock plaintext cache otherwise — so it stays accurate
either way, with no configuration. A dead 7-day session can't be detected locally, so it reads as `idle` rather
than `gone`. The pill shows `<profile> · <account>`, preferring the friendly `sso_account_name` and falling back
to the raw account ID (names get populated by `switch`, `add`, and `refresh`).

Cost is ~10ms per prompt: one short-lived process that reads two local files and deliberately never imports boto3.

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

This is positioning, not disparagement. brolly's plaintext default is deliberately thin; when you want tokens in
the OS keychain, that's an opt-in [secure mode](#secure-mode-os-keychain) rather than the always-on model of
aws-vault, granted, or aws-sso-cli.

## Design notes & caveats

Two things to own up front:

- **`switch` rewrites `~/.aws/config` globally.** A profile lives in one shared config file, so switching the
  account/role of a profile name silently retargets *any other shell* pinned to the **same profile name** on its
  next command. Safe use = **one distinct profile name per concurrent context.** If you keep two shells on the
  same account simultaneously, give them different profile names. This is the one real footgun — stated plainly.
- **Tokens live in the stock plaintext `~/.aws/sso/cache/` by default** — the very same cache the `aws` CLI uses.
  That's the thin-by-design default. When you want tokens off disk, opt into
  [secure mode](#secure-mode-os-keychain) (`brolly secure enable`), which stores them in your OS keychain and
  vends credentials via `credential_process`.

## Roadmap

- **Windows support.** The interactive picker uses `termios`/`tty` (POSIX only). A `msvcrt`-based key reader
  would let the menus run natively on Windows.
- **Passphrase-backend ergonomics for secure mode.** Smoother first-run setup for the headless-Linux encrypted-
  file keyring backend.

Shipped: [secure mode](#secure-mode-os-keychain) (opt-in OS-keychain token storage via `credential_process`),
a test suite, CI, and publication to the `fduplex` PyPI org.

## License

[Apache-2.0](LICENSE) © 2026 Full Duplex Media

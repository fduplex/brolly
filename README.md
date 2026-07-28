<p align="center">
  <img src="https://raw.githubusercontent.com/fduplex/brolly/main/assets/brolly.svg" width="84" alt="">
</p>

<h1 align="center">brolly</h1>

<p align="center"><em>British informal for umbrella — one login covers every profile under an AWS SSO session.</em></p>

<p align="center">
  <a href="https://pypi.org/project/brolly/"><img src="https://img.shields.io/pypi/v/brolly" alt="PyPI version"></a>
  <a href="https://pypi.org/project/brolly/"><img src="https://img.shields.io/pypi/pyversions/brolly" alt="Python versions"></a>
  <a href="https://github.com/fduplex/brolly/actions/workflows/ci.yml"><img src="https://github.com/fduplex/brolly/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/fduplex/brolly/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue" alt="License"></a>
</p>

A small, pure-Python CLI for AWS IAM Identity Center (SSO). Authenticate once against an `[sso-session]` and every
profile under it is usable — brolly verifies and refreshes credentials cheaply, repoints a profile's account/role
in place, adds new profiles, and ships a freshness-aware prompt pill. It never touches `$AWS_PROFILE`.

```
brolly                                  verify/refresh the current profile (same as `brolly refresh`)
brolly login [-s <session>]             force a fresh device-code login for a session
brolly switch                           repoint the current profile's account/role
brolly refresh [<profile>] [-s <session>]
brolly add <profile> [-s <session>]
brolly ls [--no-check]                  list every sso-session and its profiles, with token status
brolly secure enable|disable [-s <session>]   opt-in: keep a session's token in your OS keychain
```

## Install

```console
$ uv tool install brolly      # recommended
$ pipx install brolly
$ pip install brolly
```

Needs **Python 3.14+** and the **AWS CLI v2** on your `$PATH` — brolly shells out to `aws sso login` and
`aws configure set`; everything else goes through boto3. The AWS CLI is *not* a pip dependency
([install it separately](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)). The
arrow-key picker needs a POSIX TTY (Linux, macOS, WSL) and falls back to numeric selection without one.
[Secure mode](#secure-mode-os-keychain) is built in — nothing extra to install.

## Mental model

`~/.aws/config` has two layers:

- **`[sso-session <name>]`** — holds `sso_start_url` / `sso_region`. Logging in caches **one** token per session,
  keyed by SHA1 of the session name (`~/.aws/sso/cache/<sha1>.json`).
- **`[profile <name>]`** — references a session via `sso_session` and adds its own `sso_account_id` /
  `sso_role_name`. Any number of profiles can point at the same session.

Because the token is cached per-session, **every profile under one session shares a single login** — which is
where the name comes from.

`$AWS_PROFILE` is a fixed handle you set yourself. **brolly never touches it**: `switch` changes what a profile
resolves to, `add` creates new profiles, and `refresh` targets the `aws` CLI with `--profile` rather than mutating
your environment. No shell wrapper, nothing rewriting your env behind your back.

## Commands

### `brolly`

Shorthand for `brolly refresh` on the current `$AWS_PROFILE` — cheap, no browser unless the session is dead.

```console
$ brolly
✔  corp-dev live → arn:aws:sts::111111111111:assumed-role/AdministratorAccess/alex
```

### `brolly login [-s <session>]`

Forces a fresh device-code login for a session, unconditionally — session-scoped, not profile-scoped. Rarely
needed: `refresh` already logs in whenever a session is actually dead.

### `brolly switch`

Interactively repoints the current `$AWS_PROFILE` to a different account/role under its own session. Arrow-key
picker (`↑`/`↓` or `j`/`k`, `enter` to select, `q` to quit); accounts first, then roles (skipped when there's only
one). Rewrites `sso_account_id`, `sso_role_name`, and `sso_account_name` in place — recording the account name is
what lets the prompt show something friendlier than a raw ID.

<p align="center">
  <img src="https://raw.githubusercontent.com/fduplex/brolly/main/assets/switch.svg" width="720" alt="brolly switch: an arrow-key picker choosing an account, then a role, then the confirmation line">
</p>

The circle marks where the profile points now, the highlighted row is the cursor. `$AWS_PROFILE` is untouched —
only what it resolves to changed, which the next prompt shows.

### `brolly refresh [<profile>] [-s <session>]`

The cheap, no-browser daily driver. `-s` asserts which session you're operating in; the target profile must
actually belong to it, so crossing sessions is always deliberate:

```console
$ AWS_PROFILE=corp-dev brolly refresh corp-prod
✔  corp-prod live → arn:aws:sts::222222222222:assumed-role/AdministratorAccess/alex

$ AWS_PROFILE=customer-admin brolly refresh corp-prod
profile 'corp-prod' is under session 'corp', not 'customer' — use -s corp to target it
```

Under the hood it runs `aws sts get-caller-identity --profile <target>`, which forces credential resolution and
lets botocore refresh the access token — but only when that token is lapsed or near expiry, so a healthy one
isn't reset. If the SSO session is dead it falls through to a device-code login and retries. It also backfills
a missing `sso_account_name` (one `list_accounts` call, made only when absent).

### `brolly add <profile> [-s <session>]`

Creates a new profile under an existing session, walks the same picker, and leaves it authenticated. Refuses if
the profile already exists (use `switch`) or the session is unknown, and copies `region`/`output` from a sibling
profile when there is one.

```console
$ brolly add corp-qa                     # session inferred from $AWS_PROFILE
$ brolly add customer-admin -s customer  # explicit session
```

It does **not** change `$AWS_PROFILE`. If you Ctrl-C out of the picker the profile skeleton is already written, so
finish it with `export AWS_PROFILE=<name>` then `brolly switch` rather than re-running `add`.

### `brolly ls [--no-check]`

Lists every `sso-session` and its profiles as one aligned table, with per-session token status, expiry, and a
footer naming what `$AWS_PROFILE` currently resolves to — `ls -l` for brolly, where `ps1` is the glance. By default
it silently probes each session over the network (an SSO refresh-token grant, never an interactive login) to tell a
truly-dead session apart from a merely-lapsed token; `--no-check` skips that and reads local expiry files only.

<p align="center">
  <img src="https://raw.githubusercontent.com/fduplex/brolly/main/assets/ls-table.svg" width="900" alt="brolly ls output: two sso-sessions with their profiles, token status, accounts, roles and regions">
</p>

The current profile is the orange one. `secure` marks which profiles keep their token in the OS keychain, and the
whole table needs a **[Nerd Font](https://www.nerdfonts.com/)** for its glyphs, same as the prompt pill.

A [secured](#secure-mode-os-keychain) session that still has something in `~/.aws/sso/cache` — left by an older
brolly, or by a bare `aws sso login` — gets a warning under its session line, in the same orange as the
current-profile marker. It names what is actually there: the token blob, the OIDC client registration cached
beside it, or both.

```console
   corp     live    expires 2026-07-25 00:37 (7h19m) · auto-renews
                    ! ~/.aws/sso/cache still holds its token — the next brolly command using this session clears it, or `brolly secure enable -s corp` now
```

A session recorded as secured whose token has not moved yet reads **`stock`**, not `gone`: its profiles are still
stock, so they go on resolving credentials out of that blob perfectly well until the next brolly command finishes
the migration.

```console
   corp     stock   secured, not migrated yet — its profiles still resolve from the plaintext token
                    ! ~/.aws/sso/cache still holds its token — the next brolly command using this session clears it, or `brolly secure enable -s corp` now
```

`ls` never edits `~/.aws/config` or deletes the plaintext cache, but the default probe above isn't purely passive: a
successful silent refresh rotates that session's token and rewrites its keychain entry and expiry sidecar as it
runs. `--no-check` is the only mode that touches nothing at all.

#### Reading the expiry

The countdown is the **access token's**, not your session's. IAM Identity Center issues that token with a fixed
8-hour life on a fresh login (an hour per silent renewal after that) regardless of the access-portal session
duration your admin configured — so an 8-hour countdown says nothing about whether you have 8 hours or 90 days
before the next browser prompt. The real session lives server-side and is not visible to any client.

What *is* knowable locally is whether the session holds a refresh token, so each session line says so:

```console
   corp     live    expires 2026-07-25 00:37 (7h19m) · auto-renews
   acme     live    expires 2026-07-25 00:41 (7h23m) · no refresh token — re-login at expiry
```

`auto-renews` means new access tokens arrive silently until the access-portal session ends. `no refresh token`
means this session hits a hard wall when the countdown reaches zero — fix it with `brolly login -s <session>`.
The note is omitted, rather than guessed at, when the store can't say.

### Common tasks

| Situation | Command |
|---|---|
| Verify/refresh current creds | `brolly` |
| Force a fresh login | `brolly login` |
| Wrong account or role for the current profile | `brolly switch` |
| New profile under the current session | `brolly add <name>` then `export AWS_PROFILE=<name>` |
| New profile under a different session | `brolly add <name> -s customer` |
| Refresh a profile in another session | `brolly refresh <profile> -s <session>` |
| Interrupted a `brolly add` mid-picker | `export AWS_PROFILE=<name>` then `brolly switch` |
| See every session/profile & token status | `brolly ls` (add `--no-check` to skip the network probe) |
| Keep a session's token out of plaintext | `brolly secure enable -s <session>` |

## Shell prompt integration

`brolly ps1` renders a colored `session/profile · account` pill reflecting the **local, filesystem-only** state of
the session token — no network call, no keychain access, no boto3 import:

- **live** (amber) — token still valid.
- **idle** (grey, clock glyph) — cached but lapsed; refreshes automatically on next use.
- **gone** (red, cross glyph) — no cached token; run `brolly`.
- **plain** (neutral grey) — not an SSO profile.

<p align="center">
  <img src="https://raw.githubusercontent.com/fduplex/brolly/main/assets/prompt-states.svg" width="800" alt="brolly ps1 prompt pill shown in its live, idle, gone, and plain states">
</p>

Add it to your `PS1`. It needs a **[Nerd Font](https://www.nerdfonts.com/)** for the separators and glyphs:

```bash
export PS1='$(brolly ps1)\u@\h:\w\$ '
```

It reads whichever store the profile actually uses — the expiry sidecar for secure-mode profiles, the stock cache
otherwise — so it stays accurate with no configuration. A dead SSO session can't be detected locally, so it
reads as `idle` rather than `gone`. Cost is ~10ms per prompt.

## Secure mode (OS keychain)

By default brolly is a thin layer over the stock plaintext `~/.aws/sso/cache` — the same cache the `aws` CLI uses.
**Secure mode** moves the SSO token into your OS keychain and registers brolly as each profile's
`credential_process`, so every SDK and the `aws` CLI keep working with nothing but `$AWS_PROFILE` — no shell
wrapper, no plaintext token. It's built in; [`keyring`](https://github.com/jaraco/keyring) ships as a dependency.

Secure mode is a property of the **sso-session**. Turn it on once and every command reads the session's mode and
routes itself: `login` authorizes into the keychain, `add` writes new profiles already secured, `switch` and
`refresh` keep them that way. Your workflow is unchanged — `export AWS_PROFILE=corp-prod` and every SDK resolves
credentials through brolly.

### `brolly secure enable | disable [-s <session>]`

`enable` logs the session in (a device-code login brolly runs itself), rewrites every profile under it to use
`credential_process`, and purges what the session left in `~/.aws/sso/cache` — both credentials `aws sso login`
writes there, the token blob and the OIDC client registration it was minted under:

```console
$ brolly secure enable -s corp
→ keychain backend: pass (gpg-agent)  (saved to ~/.aws/brolly/config.json)
✓ authorized — SSO token stored in your OS keychain
✓ removed plaintext token cache for session 'corp'
✓ removed the OIDC client registration `aws sso login` cached for session 'corp' — a client secret with a ~90-day life, and brolly's own login registers its own client
✓ secure mode on for session 'corp' — its token now lives in the OS keychain
  3 profile(s) resolve credentials through it (3 converted just now)
```

A registration is only ever removed when brolly can prove it is this session's — the clientId in the session's own
token blob, or the exact name the AWS CLI derives for it. One matching neither is somebody else's client secret,
and is left alone.

It is idempotent, converting only what still needs it: re-run it to pull in a profile that arrived some other way
(a hand-edited `~/.aws/config`, an `aws configure sso`), or to re-authorize a stored token that can't renew
silently. A profile with no account/role picked yet (an interrupted `add`) has nothing to move: `enable` names it
and leaves it alone, and `refresh` against it points at `AWS_PROFILE=<profile> brolly switch` rather than a login
that can't help.

Wherever brolly converts a profile — here, or healing one on the way into a secured session — it refuses a profile
already carrying a `credential_process` it did not write. Secure mode needs that key, it *is* how a secured profile
gets credentials, but another tool's credential helper is not brolly's to overwrite: a foreign value is a conflict
rather than a line to replace. The profile is left exactly as it is, named along with the command it carries, and
the session's plaintext token stays on disk with it — a profile that did not convert is still resolving from it.

`disable` reverts every secured profile to a stock plaintext-cache profile and deletes the keychain token: a
clean, complete undo.

### How it works

- **The token** (with its refresh token) lives in the keychain under service `brolly-sso`, keyed the way botocore
  keys its own cache. brolly plugs a keychain-backed cache into botocore's token provider, so **silent refresh
  still happens** — no reimplementation, just a different vault. The device login registers its OIDC client for
  the `refresh_token` grant, so botocore's token provider can renew the access token silently instead of hitting a
  hard wall at 8 hours, and always asks for the `sso:account:access` scope — brolly needs it regardless, for the
  `list_accounts`/`get_role_credentials` calls behind `switch` and `add`.
- **A secured profile** keeps `sso_session` but moves `sso_account_id` / `sso_role_name` under `brolly_sso_*` and
  adds `credential_process`. That combination deactivates botocore's built-in SSO credential provider so
  resolution flows through brolly — otherwise botocore would find the now-absent plaintext token and fail.
- **Secure-ness is recorded, not inferred** — a `secured_sessions` list inside `~/.aws/brolly/config.json` (the
  same file that holds the chosen keychain backend). That record, not profile shape, is the authoritative answer:
  a session whose profiles are all incomplete skeletons — or which has none yet — still reads as secured, so the
  next `login` can't write a fresh refresh token back to `~/.aws/sso/cache`. Scanning profiles for `brolly_sso_*`
  is a fallback, for a session secured by an older brolly that wrote no record. Because that record is
  authoritative, brolly refuses to guess around it: a `config.json` that exists but won't parse, or won't write,
  stops the command rather than silently treating the session as unsecured.
- **Entering a secured session clears stale plaintext.** `login`, `switch`, `refresh`, `add`, and bare `brolly`
  drop whatever `~/.aws/sso/cache` still holds for the session before doing anything else. A profile still carrying
  the stock `sso_account_id`/`sso_role_name` is converted immediately beforehand — it would otherwise resolve
  credentials from that blob and rotate a live refresh token back into it on every `refresh` — and each conversion
  is named:

  ```console
  ✓ converted 'corp-legacy' to secure mode — it was still resolving credentials from ~/.aws/sso/cache
  ✓ removed plaintext token cache for session 'corp'
  ```

  `secure enable` converts up front, so a fully-enabled session has none of these; the conversion is a migration
  path for sessions an older brolly left half-converted, and the one case where brolly rewrites a profile you
  didn't name — hence a reported line each rather than silence.
- **`credential-process` reports, never removes.** The SDK spawns it non-interactively on every cold credential
  resolution with stdout owned by the credential JSON, so it rewrites neither `~/.aws/config` nor the cache
  directory: it runs unattended for whatever wanted credentials, and a blob it deleted could be one some other
  tool — a third-party SSO helper, a script, a container mount — is still reading. It names the files and leaves
  them; every interactive path still purges, so the leak closes on the next brolly command:

  ```console
  ! session 'corp' is secured, but ~/.aws/sso/cache still holds its token:
        /home/alex/.aws/sso/cache/6f2a…json
    credential-process only reports this: it runs unattended for whatever spawned it, so it will not delete a file another tool may still be reading.
    The next brolly command clears it, or clear it now:  brolly secure enable -s corp
  ```
- **The prompt pill** reads a small non-secret expiry sidecar (`~/.aws/brolly/<sha1>.json`) rather than the
  keychain, so it stays a cheap filesystem check. Nothing in `~/.aws/brolly` is secret — a session name, an expiry,
  a boolean, a backend path — but brolly still creates that directory `0700` with `0600` files, and tightens ones
  an older brolly left looser: it sits beside botocore's own `0600` `~/.aws/sso/cache`, and being the loose one of
  the pair is not a difference worth leaving to a default.
- **No environment variable to keep exported.** The chosen backend is saved to `~/.aws/brolly/config.json` and
  re-selected on every call, so resolution works from any venv, cron job, or IDE. (It does run the `brolly`
  command, so keep brolly on your `PATH`.)

### Choosing a backend

`credential-process` is spawned fresh and non-interactively on every cold credential resolution, so the backend
has to be one that stays **unlocked for your session** — macOS Keychain and gnome-keyring / KWallet already work
that way. If `keyring` can't find a usable backend, brolly says so and stops rather than failing obscurely.

`secure enable` **auto-detects**: a live OS keychain if there is one, otherwise `pass` when its store is
initialized. Whatever it picks is saved and reused, so you normally never name a backend; `--backend
<dotted.path>` overrides. Backends must live in **brolly's own environment**, since `credential_process` runs the
`brolly` executable — `keyring_pass` is bundled, and others install alongside brolly with
`uv tool install brolly --with <pkg>` (or `pipx inject brolly <pkg>`).

**Linux without a desktop: use `pass` + gpg-agent.** `pass` stores each secret gpg-encrypted and gpg-agent is the
session daemon that keeps your key unlocked, so reads are silent once it's warm — and encrypting a *write* needs
no passphrase, so token refreshes never prompt.

```console
$ sudo apt install pass            # the pass CLI itself
$ pass init <your-gpg-key-id>      # initialize the store
$ brolly secure enable -s corp     # auto-detects pass
```

gpg-agent must already be warm when `credential-process` runs, since it has no TTY to prompt on. Either raise
`max-cache-ttl` in `~/.gnupg/gpg-agent.conf` and unlock once per login, or preset the passphrase with
`gpg-preset-passphrase` for zero-touch warming — the pattern used by
[borg-backup](https://github.com/thevinchi/borg-backup).

**Other vaults.** Anything with a `keyring` backend works via `--backend` — for example `onepassword-keyring` with
a 1Password service-account token. `keyrings.alt`'s `EncryptedKeyring` is a last resort: with no daemon to keep it
unlocked it prompts in *every* new process, meaning a prompt on roughly every `aws` call and a hard failure
anywhere non-interactive.

## How it compares

No single existing tool combines what brolly does. The niche is the *combination*: native to the `sso-session`
block, in-place `switch`/`add`, never mutating `$AWS_PROFILE`, a shipped prompt pill, and pure-Python/pip.

- **[aws-sso-util](https://github.com/benkehoe/aws-sso-util)** is the closest sibling — pure-Python,
  config-native, non-invasive — but has no prompt integration, no in-place single-profile repoint, and predates
  the `sso-session` block.
- **[granted](https://granted.dev/)** and **[aws-sso-cli](https://github.com/synfinatic/aws-sso-cli)** are
  excellent, but they're Go binaries that install a shell wrapper and generate bulk static profiles.
- **[awsume](https://awsu.me/)** targets classic IAM role assumption, not Identity Center.

Positioning, not disparagement: brolly's plaintext default is deliberately thin, and keychain storage is an
opt-in rather than the always-on model of aws-vault, granted, or aws-sso-cli.

## Design notes & caveats

- **`switch` rewrites `~/.aws/config` globally.** A profile lives in one shared file, so repointing a profile
  name silently retargets *any other shell* pinned to that **same name** on its next command. Safe use = one
  distinct profile name per concurrent context. This is the one real footgun.
- **Tokens sit in the stock plaintext cache by default** — thin by design. When you want them off disk, opt into
  [secure mode](#secure-mode-os-keychain).

## Roadmap

- **Windows support.** The picker uses `termios`/`tty` (POSIX only); an `msvcrt`-based key reader would let the
  menus run natively on Windows.
- **Passphrase-backend ergonomics** — smoother first-run setup for the encrypted-file keyring backend.

## License

[Apache-2.0](LICENSE) © 2026 Full Duplex Media

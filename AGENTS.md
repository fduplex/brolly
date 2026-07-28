# AGENTS.md

`brolly` — a pure-Python CLI for AWS IAM Identity Center (SSO). Source in `src/brolly`, tests in `tests`.

## Checks

What CI runs, in order — run all four before calling work done:

```bash
uv run ruff format src tests   # CI uses --check; format for real locally
uv run ruff check src tests
uv run ty check src
uv run pytest
```

## `src/brolly/prompt.py` is hot

It renders on every shell prompt, so it stays **stdlib-only** — no boto3, no keyring, no network, no subprocess.
`tests/test_prompt.py` enforces the boto3 half of that; the rest is on you.

## Secure mode dispatches per session, not per command

`brolly secure` has exactly two subcommands, `enable`/`disable` — there is no `secure login` or other
secure-flavoured twin. Every other command (`login`, `refresh`, `switch`, `add`, bare `brolly`) calls
`_session_is_secure()` in `cli.py` and routes itself into the keychain path when the session is secured. If you
add a new top-level command that establishes or refreshes credentials, wire it the same way — a command that
shells out to `aws sso login` (or otherwise writes the plaintext cache) without checking the session's mode first
will silently overwrite a secured session's refresh token in `~/.aws/sso/cache`, which is the bug this dispatch
rule exists to prevent.

`cli._enter_secure_session` is the one door into the keychain paths, and its four steps are ordered:
`keychain.preflight_keychain`, back-fill the secured-session record, `keychain.heal_session_profiles` (which
shares `_reshape_session_profiles` with `secure enable`, so the two can't disagree), then `purge_session_plaintext`.
The preflight runs first because every step after it mutates state — rewriting `~/.aws/config`, deleting a token —
on the strength of a keychain that must therefore be known to work before any of that happens. Healing removes the
last profile reading the plaintext blob, which is what lets the purge run unconditionally — reorder that pair and
the purge starts refusing again. `secure enable` reshapes then purges in the same order and for the same reason:
it used to purge unconditionally *before* reshaping, which was only safe on the assumption that reshaping always
converts every profile it touches. Now that a conversion can fail and leave a profile in stock shape (an
`aws configure set` that doesn't stick, an odd section header), purging first could delete the blob out from under
it — so `secure enable` reshapes, verifying each conversion, then purges through the same guarded
`purge_session_plaintext` every other path uses.

What the purge clears is both credentials `aws sso login` writes: the token blob *and* the OIDC client
registration it was minted under (`_plaintext_leftovers`). A registration names no session, so one is only ever
deleted on a positive attribution — the clientId in this session's token blob, or the exact name the AWS CLI
derives — and one matching neither is left alone. Never widen that: deleting a stranger's client secret is a worse
failure than leaving one behind.

Two paths deliberately stop short of the purge. `credential-process` does not call it at all: it runs unattended
for whatever spawned it, so it reports through `report_session_plaintext` and deletes nothing — the guards only
recognise consumers that exist as AWS profiles, and a script or container mount reading that blob is invisible to
them. It must not rewrite `~/.aws/config` either. And `_secure_profile` refuses a profile that already carries a
`credential_process` brolly did not write: it names the value, converts nothing, and the unconverted profile then
holds the purge back on its own account. Secure mode owns that key, but a user's credential helper is not brolly's
to overwrite.

`ls` is the one command that neither heals nor purges — it reads, and that is load-bearing. It reports leftovers
through the same `_plaintext_leftovers` attribution the purge deletes by (so it can never name a file the purge
would not touch), and gives a secured session whose token has not moved yet its own `stock` status: profiles still
stock plus a token blob still on disk is a migration waiting for the next command, not the dead session `gone`
would claim.

## brolly's own files live under `~/.aws/brolly`

Its config and the expiry sidecars, written through `cli._ensure_brolly_dir` + `cli._atomic_write` — which land
the directory at `0700` and the files at `0600`, tightening whatever an older brolly left. Nothing in them is
secret; the point is not to be the loose file beside botocore's own `0600` `~/.aws/sso/cache`. Write anything new
there the same way rather than with a bare `write_text`, and note that `_atomic_write` keys the mode off the
target's directory: on a file that is *not* brolly's — `~/.aws/config` — it preserves the user's own mode instead.

## Regenerating the README illustrations

Every `.svg` under `assets/` is generated, never hand-edited:

```bash
uv run python assets/gen_prompt_states.py   # -> prompt-states.svg  (the ps1 pill's four states)
uv run python assets/gen_ls_table.py        # -> ls-table.svg       (a `brolly ls` run)
uv run python assets/gen_switch.py          # -> switch.svg         (a `brolly switch` session)
```

The kit under them: `termsvg.py` (palette, glyph outlines, window chrome, the pill), `ansi.py` (a tiny terminal
— it replays cursor moves and reverse video, then paints the resulting grid), `climap.py` (cli.py's ANSI codes
and glyph codepoints, read back off the module so they can't desync).

`gen_ls_table.py` and `gen_switch.py` run the real `cmd_ls` / `cmd_switch` and screenshot what they write, so
those two can't drift — but re-run them after touching `ls` or the picker. Only what would reach the network,
the keyboard, or `~/.aws` is stubbed; `now` and `TZ=UTC` are pinned so the committed SVGs are reproducible.
Leave those pins alone. `gen_prompt_states.py` does draw its own copy, so keep its colours in step with
`_STYLES` in `src/brolly/prompt.py` and its labels in the shape the pill really prints (`session/profile ·
account`).

The icons in both are real Nerd Font outlines, baked into `assets/nerd-glyphs.json` so README readers need no
font. That file is already committed — only re-extract when the glyph set in `prompt.py` or `cli.py` changes:

```bash
curl -sLo /tmp/nf.zip https://github.com/ryanoasis/nerd-fonts/releases/latest/download/NerdFontsSymbolsOnly.zip
unzip -o /tmp/nf.zip -d /tmp/nf
uv run python assets/extract_glyphs.py /tmp/nf/SymbolsNerdFont-Regular.ttf   # then re-run the generator
```

Add the new codepoint to `WANTED` in `extract_glyphs.py` first. `fontTools` is a dev dependency; the font itself
is not vendored. To eyeball the result, serve the repo (`uv run python -m http.server`) and screenshot the SVG in
a browser — ImageMagick renders it poorly.

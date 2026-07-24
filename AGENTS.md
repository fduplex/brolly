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

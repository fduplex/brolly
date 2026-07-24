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

Both `.svg`s under `assets/` are generated, never hand-edited. Shared drawing primitives live in `termsvg.py`.

```bash
uv run python assets/gen_prompt_states.py   # -> assets/prompt-states.svg (the ps1 pill's four states)
uv run python assets/gen_ls_table.py        # -> assets/ls-table.svg     (a `brolly ls` run)
```

`gen_ls_table.py` calls the real `cmd_ls` against a synthetic config and paints the ANSI it emits, so the table
can't drift — but re-run it after touching `ls`. It pins `now` and `TZ=UTC` so the committed SVG is
reproducible; leave those alone. `gen_prompt_states.py` does draw its own copy, so keep its colours in step with
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

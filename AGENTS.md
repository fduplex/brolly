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

## Regenerating the README illustration

`assets/prompt-states.svg` is generated, never hand-edited. After changing the pill's palette, copy, or layout:

```bash
uv run python assets/gen_prompt_states.py   # rewrites assets/prompt-states.svg — commit it
```

Keep its colours in sync with `_STYLES` in `src/brolly/prompt.py`, and its labels in the same shape the pill
actually prints (`session/profile · account`).

The pill's icons are real Nerd Font outlines, baked into `assets/nerd-glyphs.json` so README readers need no
font. That file is already committed — only re-extract when the glyph set in `prompt.py` changes:

```bash
curl -sLo /tmp/nf.zip https://github.com/ryanoasis/nerd-fonts/releases/latest/download/NerdFontsSymbolsOnly.zip
unzip -o /tmp/nf.zip -d /tmp/nf
uv run python assets/extract_glyphs.py /tmp/nf/SymbolsNerdFont-Regular.ttf   # then re-run the generator
```

Add the new codepoint to `WANTED` in `extract_glyphs.py` first. `fontTools` is a dev dependency; the font itself
is not vendored. To eyeball the result, serve the repo (`uv run python -m http.server`) and screenshot the SVG in
a browser — ImageMagick renders it poorly.

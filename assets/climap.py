"""What `src/brolly/cli.py` writes to a terminal, mapped to how this kit draws it.

Both the ANSI codes and the glyph codepoints are read back off cli.py rather than repeated here, so swapping a
glyph or a colour there cannot silently desync an illustration.
"""

from brolly import cli

from termsvg import DIM, FG, GREEN, ORANGE, RED

# SGR parameter string -> hex. Reverse video ('7') is handled by the painter, not here.
COLORS = {'0': FG, '2': DIM, '31': RED, '32': GREEN, '38;5;214': ORANGE}

GLYPHS = {
    cli._AWS: 'aws',
    cli._PULSE: 'pulse',
    cli._USER: 'user',
    cli._LOCK: 'lock',
    cli._ACCT: 'account',
    cli._ROLE: 'role',
    cli._GLOBE: 'globe',
    cli._CHECK: 'check',
    cli._CLOCK: 'clock',
    cli._CROSS: 'cross',
    cli._CURRENT: 'check_circle',
    cli._CURSOR: 'caret_right',
}

GLYPH_EM = 12.5  # every glyph set at one em, the way the terminal sets them — not tuned icon by icon

"""A very small terminal: enough of one to screenshot brolly's output without a terminal.

`Screen` consumes what a command writes to stdout and keeps the character grid that a terminal would end up
showing — which matters for the interactive picker, where each keystroke rewinds the cursor (`ESC[nA`) and
overdraws the previous frame. Painting the *final* grid is what a screenshot of that session would show.

`paint` turns that grid into SVG on the monospace grid: Nerd Font codepoints become outlines, reverse-video
runs become a filled rect with the background colour drawn through the text, everything else is a text run.

Only the escapes brolly actually emits are implemented (SGR colours, reverse video, erase-to-end-of-line,
cursor-up, cursor visibility). Anything else is skipped rather than guessed at.
"""

import io
import sys
from collections.abc import Callable
from dataclasses import dataclass
import re

from termsvg import CW, ink_height, nf_glyph, text

_CSI = re.compile(r'\033\[([0-9;?]*)([A-Za-z])')
_RESET = '0'


@dataclass(slots=True)
class Cell:
    ch: str
    sgr: str  # the SGR parameter string in force, e.g. '2' or '38;5;214'
    reverse: bool


class Screen:
    """A grid of cells the writer paints into. Lines grow on demand; there is no scrollback and no width."""

    def __init__(self) -> None:
        self.rows: list[list[Cell]] = [[]]
        self.r = self.c = 0
        self.sgr = _RESET
        self.reverse = False

    def _row(self) -> list[Cell]:
        while len(self.rows) <= self.r:
            self.rows.append([])
        return self.rows[self.r]

    def _put(self, ch: str) -> None:
        row = self._row()
        while len(row) <= self.c:
            row.append(Cell(' ', _RESET, False))
        row[self.c] = Cell(ch, self.sgr, self.reverse)
        self.c += 1

    def _csi(self, params: str, final: str) -> None:
        if final == 'm':
            if params in ('', _RESET):
                self.sgr, self.reverse = _RESET, False
            elif params == '7':
                self.reverse = True
            elif params == '27':
                self.reverse = False
            else:
                self.sgr = params
        elif final == 'K':  # erase from the cursor to end of line
            row = self._row()
            del row[self.c :]
        elif final == 'A':  # cursor up: the picker's redraw
            self.r = max(0, self.r - int(params or 1))

    def write(self, s: str) -> None:
        pos = 0
        for m in _CSI.finditer(s):
            self._text(s[pos : m.start()])
            self._csi(*m.groups())
            pos = m.end()
        self._text(s[pos:])

    def _text(self, s: str) -> None:
        for ch in s:
            if ch == '\n':
                self.r, self.c = self.r + 1, 0
                self._row()
            elif ch == '\r':
                self.c = 0
            else:
                self._put(ch)

    def trimmed(self) -> list[list[Cell]]:
        """The grid with blank leading/trailing lines and trailing blanks on each line dropped."""
        rows = [list(r) for r in self.rows]
        for row in rows:
            while row and row[-1].ch == ' ':
                row.pop()
        while rows and not rows[0]:
            rows.pop(0)
        while rows and not rows[-1]:
            rows.pop()
        return rows


class _Tty(io.StringIO):
    """A stream that claims to be a terminal, so commands take their interactive/coloured path.

    `fileno` answers 0 for the picker, which asks for one before handing it to termios — stub termios out too.
    """

    def isatty(self) -> bool:
        return True

    def fileno(self) -> int:
        return 0


def record(run: Callable[[], None]) -> Screen:
    """Run a command with stdin/stdout looking like a terminal; return the screen its output painted."""
    out, stdio = _Tty(), (sys.stdout, sys.stdin)
    sys.stdout, sys.stdin = out, _Tty()
    try:
        run()
    finally:
        sys.stdout, sys.stdin = stdio
    screen = Screen()
    screen.write(out.getvalue())
    return screen


def paint(
    rows: list[list[Cell]],
    *,
    x0: float,
    y0: float,
    lineh: float,
    colours: dict[str, str],
    glyphs: dict[str, str],
    glyph_em: float,
    bg: str,
) -> list[str]:
    """Draw a grid at (x0, y0), one line every `lineh`. `colours` maps SGR params to hex, `glyphs` chars to names."""
    parts: list[str] = []
    for r, row in enumerate(rows):
        y = y0 + r * lineh + lineh / 2
        run, run_col, style = '', 0, (_RESET, False)

        for c, cell in enumerate(row):
            is_glyph = cell.ch in glyphs
            if is_glyph or (cell.sgr, cell.reverse) != style:
                parts += _run(run, x0 + run_col * CW, y, lineh, colours[style[0]], style[1], bg)
                run, run_col, style = '', c, (cell.sgr, cell.reverse)
            if is_glyph:
                name = glyphs[cell.ch]
                colour = bg if cell.reverse else colours[cell.sgr]
                parts.append(nf_glyph(name, x0 + (c + 0.5) * CW, y, colour, ink_height(name, glyph_em)))
                run_col = c + 1
                continue
            run += cell.ch
        parts += _run(run, x0 + run_col * CW, y, lineh, colours[style[0]], style[1], bg)
    return parts


def _run(run: str, x: float, y: float, lineh: float, colour: str, reverse: bool, bg: str) -> list[str]:
    """One same-styled stretch of a line: reverse video paints a block, a rule paints a rect, text paints text."""
    s, lead = run.strip(), len(run) - len(run.lstrip())
    if not s:
        return []
    if reverse:
        return [
            f'<rect x="{x:.2f}" y="{y - lineh / 2:.2f}" width="{len(run) * CW:.2f}" height="{lineh:.2f}" '
            f'fill="{colour}"/>',
            text(x + lead * CW, y, s, bg),
        ]
    if set(s) == {'─'}:  # a rule: one rect, so no viewer can leave gaps between the dashes
        return [f'<rect x="{x + lead * CW:.2f}" y="{y:.2f}" width="{len(s) * CW:.2f}" height="1" fill="{colour}"/>']
    return [text(x + lead * CW, y, s, colour)]

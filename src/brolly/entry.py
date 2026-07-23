"""Console entry point.

`ps1` is routed to the stdlib-only prompt module *before* anything imports boto3 — that import alone costs ~70ms,
which would be paid on every single shell prompt. Every other command goes through the full CLI.
"""

import sys


def app() -> None:
    if sys.argv[1:2] == ['ps1']:
        from brolly.prompt import main

        raise SystemExit(main())

    from brolly.cli import app as cli_app

    cli_app()

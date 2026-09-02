"""Entry point used by `python -m logsentinel`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())

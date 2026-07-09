"""One-shot migration of a legacy AETHER-IDA config into AETHER Next.

Run as a module: ``python -m scripts.migrate_legacy_config`` (see ``__main__``).
"""


def main() -> int:
    from .cli import main as cli_main

    return cli_main()


__all__ = ["main"]

if __package__:
    from .cli import main
else:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parents[2]))
    from scripts.migrate_legacy_config.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

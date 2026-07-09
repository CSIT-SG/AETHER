# Contributing

Requires:
  - `python 3.12 or 3.13`
  - `ida >= 9.2`
  - `mypy` IDE extension
  - [`bun`](https://bun.com) for documentation

## IDE setup
1. Set your language server's option `Extra Paths` to `C:\Program Files\IDA Professional 9.x\python` (replace as needed). 
2. Run `uv sync --all-packages` (`--allow-insecure-host <host>` if any ssl error).
3. `cd apps/docs && bun i` to install the packages for the docs.
4. Add the pre-commit hooks `uv run pre-commit install`.

## Developer tooling

- Lint: `uv run ruff check`
- Format: `uv run ruff format`
- Unit tests: `uv run pytest apps/*/tests/unit packages/*/tests/unit`
- Integration tests: `uv run pytest apps/*/tests/integration packages/*/tests/integration`
  - You should set the environment variable `IDADIR="C:\Program Files\IDA Professional 9.2"` (or your ida install directory).

For more information, go to the respective package `README.md`.

## Config migration tool

If you want to carry an old install's config into AETHER Next, use the one-shot
migration tool at `scripts/migrate_legacy_config`. It brings settings from a
legacy `AppData\Local\AETHER-IDA` install into the current `AETHER-next` global config.

**`cd` into the tool's directory and run it from there** (`python .` runs the
package):

```sh
cd scripts/migrate_legacy_config

# Dry run first: show what would change and which legacy fields are dropped.
uv run python . --source AETHER-IDA --dry-run --dropped

# Write a migration report without touching the destination config.
# Omit the path and it writes migration-report.json into this directory.
uv run python . --source AETHER-IDA --dry-run --report

# Migrate a specific file instead of auto-discovering legacy install paths.
uv run python . --source-path path\to\config.json

# Drop --dry-run to actually write the AETHER Next config (will backup existing AETHER Next config).
uv run python . --source AETHER-IDA
```

The tool only migrates settings AETHER Next exposes as static `ConfigModel` fields and runtime-supported values. If a legacy field has no static AETHER Next setting yet, keep it in `DROPPED_FIELD_NOTES` in `scripts/migrate_legacy_config/mapping.py`.

When adding support for a dropped legacy setting:

1. Add a typed Pydantic field in `packages/utils/src/aether_utils/config/models.py`.
2. Ensure runtime code actually reads the new setting.
3. Move the legacy key from `DROPPED_FIELD_NOTES` to `FIELD_MAPPINGS`.
4. Update `scripts/migrate_legacy_config/tests/test_migration.py`.
5. Run `uv run pytest scripts/migrate_legacy_config/tests/test_migration.py`.

See `scripts/migrate_legacy_config/README.md` for the module layout and flag reference.

## Release

Releases are published via the [`release.yml`](workflows/release.yml) GitHub Actions workflow.
It builds Python wheels for all distributable packages, verifies the docs build, tags the commit, and publishes a GitHub Release with the wheels as assets.

### Triggering a release

Go to **Actions -> Release -> Run workflow** and optionally enter a version number.

- If version is omitted, the workflow reads from the [`VERSION`](../VERSION) file at repo root.
- If the tag already exists, the workflow fails with an error telling you to bump the version.

To trigger from the CLI:

```sh
# Uses VERSION file
gh workflow run release.yml

# Explicit version
gh workflow run release.yml -f version=1.2.3
```


### Local testing with act

[act](https://github.com/nektos/act) runs GitHub Actions locally against a Docker container. Ensure the Docker daemon is running before using act.


Enter github secret and use act to test:

```sh
# Requires Docker and act installed
echo "GITHUB_TOKEN=<your_token>" > .secrets

act workflow_dispatch -j release \
  -W .github/workflows/release.yml \
  --secret-file .secrets \
  --input version=0.1.0
```

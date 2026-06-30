# Release

Releases are published via the [`release.yml`](workflows/release.yml) GitHub Actions workflow.
It builds Python wheels for all distributable packages, verifies the docs build, tags the commit, and publishes a GitHub Release with the wheels as assets.

## Triggering a release

Go to **Actions → Release → Run workflow** and optionally enter a version number.

- If version is omitted, the workflow reads from the [`VERSION`](../VERSION) file at repo root.
- If the tag already exists, the workflow fails with an error telling you to bump the version.

To trigger from the CLI:

```sh
# Uses VERSION file
gh workflow run release.yml

# Explicit version
gh workflow run release.yml -f version=1.2.3
```

## What it does

1. Resolves the release version (input or `VERSION` file)
2. Installs dependencies via `uv sync --all-packages`
3. Builds wheels for all packages that declare a `[build-system]` in their `pyproject.toml`
4. Verifies the docs Docker image builds cleanly
5. Creates and pushes a `v{version}` git tag
6. Publishes a GitHub Release with wheels and sdists as assets

## Adding a new publishable package

Add `[build-system]` to the package's `pyproject.toml`:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

The release workflow picks it up automatically — no changes to the workflow needed.

## Local testing with act

**Docker** is required as the runtime for act.
Download from [docker.com/get-started](https://www.docker.com/get-started) and ensure the Docker daemon is running before using act.

**act** runs GitHub Actions locally against a Docker container.

```sh
# macOS
brew install act

# Windows
winget install nektos.act
```

Pull the runner image once before first use:

```sh
docker pull catthehacker/ubuntu:act-22.04
```

Create `.actrc` file at repo root:
```
-P ubuntu-latest=catthehacker/ubuntu:act-22.04
--container-daemon-socket /var/run/docker.sock
```

Enter github secret and use act to test:

```sh
# Requires Docker and act installed
echo "GITHUB_TOKEN=<your_token>" > .secrets

act workflow_dispatch -j release \
  -W .github/workflows/release.yml \
  --secret-file .secrets \
  --input version=0.1.0
```
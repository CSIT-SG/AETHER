# AETHER Benchmark

Standalone LLM-based evaluation tool for reverse engineering tool outputs. Evaluates either an IDA database or a chatbot markdown transcript against a human-written rubric.

## Usage

```bash
# Evaluate an IDB
aether-benchmark --rubric path/to/rubric.yaml --idb path/to/sample.i64 --ida-dir "C:\Program Files\IDA Professional 9.2" --api-key <API_KEY>

# Evaluate a markdown transcript
aether-benchmark --rubric path/to/rubric.yaml --doc path/to/transcript.md --api-key <API_KEY>
```

## Options

| Flag | Required | Description |
|------|----------|--------------|
| `--rubric <path>` | Yes | Path to the rubric YAML file |
| `--idb <path>` | Exactly one of `--idb` / `--doc` | Path to the IDB/i64 file to evaluate |
| `--doc <path>` | Exactly one of `--idb` / `--doc` | Path to the chatbot transcript markdown file |
| `--api-key <key>` | Yes (or via env) | OpenRouter/OpenAI API key. Falls back to `OPENROUTER_API_KEY` |
| `--ida-dir <path>` | Only with `--idb` | IDA Pro installation directory. Falls back to `IDADIR` |
| `--model <slug>` | No | Model slug to use (default: `openai/gpt-5-mini`) |
| `--base-url <url>` | No | API base URL (default: `https://openrouter.ai/api/v1`) |
| `-v`, `--verbose` | No | Show detailed per-entry results |
| `-o`, `--output <path>` | No | Write the benchmark result as JSON to this file |

## Rubric Format

Rubrics are written as YAML and require a `version` field. Its major component must match this package's major version (see [Versioning](#versioning)) — a mismatch is a hard error at parse time. For the full schema and writing guidelines, run the docs site locally (see [apps/docs/README.md](../../apps/docs/README.md)) and browse to `http://localhost:3000/development/benchmark/schema`.

## Versioning

This package is versioned `major.minor`.

- **Major** — the rubric schema changed in a way that breaks existing rubric YAML files written against a previous version.
- **Minor** — the rubric schema changed, but existing rubric YAML files remain valid.

Pin your rubrics to a compatible major version of `aether_benchmark`.

### Making a bump

From `packages/benchmark`, run:

```bash
uv run cz bump --increment MAJOR   # breaking rubric schema change
uv run cz bump --increment MINOR   # non-breaking rubric schema change
```

This updates `version` in `pyproject.toml`, commits, and tags the release as `benchmark-<version>`.

> commitizen always writes a trailing patch digit (e.g. `0.2.0`, `1.0.0`) 

## Requirements

- Python 3.12+
- IDA Pro 9.x (for `--idb` mode)
- OpenRouter or OpenAI API key

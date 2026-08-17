# AETHER Benchmark

Standalone LLM-based evaluation tool for reverse engineering tool outputs.

Evaluates an already-processed IDB against a human-written rubric using an LLM
(via OpenRouter). No AETHER-internal dependencies — only external PyPI packages
(pydantic, pyyaml, openai, openai-agents).

## Usage

```bash
aether-benchmark --idb <path.i64> --rubric <rubric.yaml> --api-key <key>
```

Or with **OpenRouter API key** set in your environment:

```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
aether-benchmark --idb my_binary.i64 --rubric example_rubric.yaml --verbose
```

## Options

| Flag | Description |
|------|-------------|
| `--idb <path>` | Path to the IDB/i64/binary to evaluate |
| `--rubric <path>` | Path to the rubric YAML file |
| `--api-key <key>` | OpenRouter/OpenAI API key (or `OPENROUTER_API_KEY` env var) |
| `--model <slug>` | Model to use (default: `qwen/qwen3.7-flash`) |
| `--base-url <url>` | API base URL (default: `https://openrouter.ai/api/v1`) |
| `--ida-dir <path>` | IDA Pro installation directory |
| `--verbose` / `-v` | Show detailed per-entry results |
| `--json` | Output raw JSON only |

## Rubric Format

See [example_rubric.yaml](./example_rubric.yaml) for a sample.

## Requirements

- Python 3.12+
- IDA Pro 9.x (for `--idb` mode — requires the `idapro` PyPI package)
- OpenRouter or OpenAI API key

## IDA Directory

The benchmark needs to know where IDA Pro is installed. Provide it via:

```bash
aether-benchmark --idb binary.i64 --rubric rubric.yaml --api-key <key> --ida-dir "C:\Program Files\IDA Professional 9.2"
```

Or set the `IDADIR` environment variable:

```bash
export IDADIR="C:\Program Files\IDA Professional 9.2"
aether-benchmark --idb binary.i64 --rubric rubric.yaml --api-key <key>
```

The `idapro` package must be importable — `IDADIR` must point to the IDA installation that contains `idalib.dll`. No auto-detection is performed; the benchmark will fail with a clear error if neither `--ida-dir` nor `IDADIR` is set.

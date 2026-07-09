# migrate_legacy_config

One-shot migration of a legacy `AETHER-IDA` config into the current AETHER Next config.

```sh
python -m scripts.migrate_config.run
```

It reads the legacy `AETHER-IDA` config, converts the settings AETHER Next
supports (provider, subagents, debug, tls) into the new nested shape, checks the
essentials, backs up any existing AETHER Next config (timestamped), and writes the
result. Model ids are resolved to the friendly names from `MODEL_LIST`.

Works on Windows and Linux — the config locations are resolved the same way the
app does (`platformdirs`, reproduced in stdlib):

| OS | Legacy AETHER-IDA | AETHER Next destination |
| --- | --- | --- |
| Windows | `%LOCALAPPDATA%\AETHER-IDA\config.json` | `%LOCALAPPDATA%\AETHER-next\_global\config.json` |
| Linux | `~/.local/share/AETHER-IDA/config.json` | `~/.local/share/_global/config.json` |

Each run prints the `legacy_key -> destination` mapping and the keys it skipped
(anything with no AETHER Next setting). The only hand-maintained piece is
`MAPPING`; the skip list is derived from it.

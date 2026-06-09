import json
from pathlib import Path

import pytest
from aether_utils.config import load_config


def test_load_config_creates_default_file(mock_config_file: Path) -> None:
    assert not mock_config_file.exists()
    print(f"Testing with mock config file at: {mock_config_file}")

    cfg = load_config(mock_config_file)

    assert mock_config_file.exists()
    assert cfg.openai_model == "qwen/qwen3-coder"
    assert cfg.subagents.gatherer_model == cfg.openai_model

    saved = json.loads(mock_config_file.read_text(encoding="utf-8"))
    assert saved["openai_model"] == cfg.openai_model
    assert saved["subagents"]["gatherer_model"] == cfg.openai_model


def test_load_config_reads_existing_file(mock_config_file: Path) -> None:
    raw = {
        "openai_api_key": "test-key",
        "openai_model": "openai/gpt-oss-120b",
        "model_list": {"OpenAI: gpt-oss-120b": "openai/gpt-oss-120b"},
        "subagents": {"gatherer_model": ""},
    }
    mock_config_file.write_text(json.dumps(raw, indent=2), encoding="utf-8")

    cfg = load_config(mock_config_file)

    assert cfg.openai_api_key == "test-key"
    assert cfg.openai_model == "openai/gpt-oss-120b"
    assert cfg.subagents.gatherer_model == cfg.openai_model


def test_load_config_rejects_unknown_subagent_model(mock_config_file: Path) -> None:
    raw = {
        "openai_model": "qwen/qwen3-coder",
        "model_list": {"Qwen: Qwen3 Coder 480B A35B": "qwen/qwen3-coder"},
        "subagents": {"gatherer_model": "unknown-model"},
    }
    mock_config_file.write_text(json.dumps(raw, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="GATHERER_MODEL"):
        load_config(mock_config_file)

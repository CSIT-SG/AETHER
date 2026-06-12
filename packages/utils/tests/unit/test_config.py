import json
from pathlib import Path
from unittest.mock import patch

import pytest
from aether_utils.config.config import ConfigManager
from aether_utils.config.models import ConfigModel
from pydantic import ValidationError

VALID_MINIMAL = {
    "provider": {
        "type": "openrouter",
        "api_key": "sk-test",
        "models": {"GPT-4o": "openai/gpt-4o"},
        "default_model": "GPT-4o",
    }
}

VALID_FULL = {
    "provider": {
        "type": "openrouter",
        "api_key": "sk-test",
        "models": {
            "GPT-4o": "openai/gpt-4o",
            "Claude Sonnet": "anthropic/claude-sonnet-4-6",
            "Qwen Coder": "qwen/qwen3-coder",
        },
        "default_model": "GPT-4o",
        "extra_body": {"transforms": ["middle-out"]},
    },
    "subagents": {
        "gatherer_model": "Claude Sonnet",
        "annotator_model": "Qwen Coder",
        "ai_decomp_model": None,
        "single_analysis_model": None,
        "struct_creator_model": None,
        "index_agent_model": None,
    },
    "features": {
        "annotator": {"enabled": True},
        "deobfuscator": None,
        "chatbot": {},
        "gatherer": None,
        "ai_decomp": None,
    },
    "debug": True,
    "tls": {
        "custom_ca_cert_path": "/certs/ca.pem",
        "client_cert_path": "/certs/client.crt",
        "client_key_path": "/certs/client.key",
    },
}

VALID_SUBAGENTS_ALL_NULL = {
    "provider": {
        "type": "openrouter",
        "api_key": "sk-test",
        "models": {"GPT-4o": "openai/gpt-4o"},
        "default_model": "GPT-4o",
    },
    "subagents": {
        "gatherer_model": None,
        "annotator_model": None,
        "ai_decomp_model": None,
        "single_analysis_model": None,
        "struct_creator_model": None,
        "index_agent_model": None,
    },
}

VALID_EXTRA_BODY_NULL = {
    "provider": {
        "type": "other",
        "api_key": "sk-test",
        "models": {"Local Model": "local/mistral-7b"},
        "default_model": "Local Model",
        "extra_body": None,
    }
}

# Two keys that differ only by case — both valid, default is the lowercase one
VALID_CASE_SENSITIVE_KEYS = {
    "provider": {
        "type": "openrouter",
        "api_key": "sk-test",
        "models": {
            "gpt-4o": "openai/gpt-4o",
            "GPT-4o": "openai/gpt-4o-upper",
        },
        "default_model": "gpt-4o",
    }
}

# --- invalid ---

INVALID_DEFAULT_IS_MODEL_ID = {
    "provider": {
        "type": "openrouter",
        "api_key": "sk-test",
        "models": {"GPT-4o": "openai/gpt-4o"},
        "default_model": "openai/gpt-4o",  # ID, not key
    }
}

INVALID_DEFAULT_NOT_IN_MODELS = {
    "provider": {
        "type": "openrouter",
        "api_key": "",
        "models": {"GPT-4o": "openai/gpt-4o"},
        "default_model": "Claude Sonnet",  # not present
    }
}

INVALID_EMPTY_MODELS = {
    "provider": {
        "type": "openrouter",
        "api_key": "",
        "models": {},
        "default_model": "GPT-4o",
    }
}

INVALID_SUBAGENT_NOT_IN_PROVIDER = {
    "provider": {
        "type": "openrouter",
        "api_key": "sk-test",
        "models": {"GPT-4o": "openai/gpt-4o"},
        "default_model": "GPT-4o",
    },
    "subagents": {"gatherer_model": "Claude Sonnet"},  # not in provider models
}

INVALID_SUBAGENT_USES_MODEL_ID = {
    "provider": {
        "type": "openrouter",
        "api_key": "sk-test",
        "models": {"GPT-4o": "openai/gpt-4o"},
        "default_model": "GPT-4o",
    },
    "subagents": {"gatherer_model": "openai/gpt-4o"},  # ID, not key
}

INVALID_PROVIDER_TYPE = {
    "provider": {
        "type": "unsupported_proxy",
        "api_key": "sk-test",
        "models": {"GPT-4o": "openai/gpt-4o"},
        "default_model": "GPT-4o",
    }
}

INVALID_MISSING_PROVIDER = {"debug": True}

INVALID_MISSING_DEFAULT_MODEL_FIELD = {
    "provider": {
        "type": "openrouter",
        "api_key": "",
        "models": {"GPT-4o": "openai/gpt-4o"},
        # default_model omitted entirely
    }
}

INVALID_DEFAULT_WRONG_CASE = {
    "provider": {
        "type": "openrouter",
        "api_key": "sk-test",
        "models": {"GPT-4o": "openai/gpt-4o"},
        "default_model": "gpt-4o",  # wrong case
    }
}


class TestValidConfigs:
    def test_minimal(self) -> None:
        cfg = ConfigModel.model_validate(VALID_MINIMAL)
        assert cfg.provider.default_model == "GPT-4o"
        assert cfg.subagents is None
        assert cfg.features is None
        assert cfg.debug is None
        assert cfg.tls is None

    def test_full(self) -> None:
        cfg = ConfigModel.model_validate(VALID_FULL)
        assert cfg.debug is True
        assert cfg.tls is not None
        assert cfg.tls.custom_ca_cert_path == "/certs/ca.pem"
        assert cfg.subagents is not None
        assert cfg.subagents.gatherer_model == "Claude Sonnet"
        assert cfg.subagents.ai_decomp_model is None

    def test_subagents_all_null(self) -> None:
        """Subagents block present but every override is None — validator should pass."""
        cfg = ConfigModel.model_validate(VALID_SUBAGENTS_ALL_NULL)
        assert cfg.subagents is not None
        assert cfg.subagents.gatherer_model is None

    def test_extra_body_null(self) -> None:
        cfg = ConfigModel.model_validate(VALID_EXTRA_BODY_NULL)
        assert cfg.provider.extra_body is None

    def test_case_sensitive_keys_coexist(self) -> None:
        """'gpt-4o' and 'GPT-4o' are distinct keys; lowercase one is a valid default."""
        cfg = ConfigModel.model_validate(VALID_CASE_SENSITIVE_KEYS)
        assert cfg.provider.default_model == "gpt-4o"
        assert "GPT-4o" in cfg.provider.models


class TestInvalidConfigs:
    def test_default_is_model_id_not_key(self) -> None:
        """Regression: model ID passed as default_model instead of friendly name."""
        with pytest.raises(ValidationError, match="Default model must be listed"):
            ConfigModel.model_validate(INVALID_DEFAULT_IS_MODEL_ID)

    def test_default_not_in_models(self) -> None:
        with pytest.raises(ValidationError, match="Default model must be listed"):
            ConfigModel.model_validate(INVALID_DEFAULT_NOT_IN_MODELS)

    def test_empty_models_dict(self) -> None:
        with pytest.raises(ValidationError, match="Default model must be listed"):
            ConfigModel.model_validate(INVALID_EMPTY_MODELS)

    def test_subagent_model_not_in_provider(self) -> None:
        with pytest.raises(ValidationError, match="not in the provider's model list"):
            ConfigModel.model_validate(INVALID_SUBAGENT_NOT_IN_PROVIDER)

    def test_subagent_uses_model_id_not_key(self) -> None:
        """Subagent override uses raw model ID instead of friendly name key."""
        with pytest.raises(ValidationError, match="not in the provider's model list"):
            ConfigModel.model_validate(INVALID_SUBAGENT_USES_MODEL_ID)

    def test_invalid_provider_type(self) -> None:
        with pytest.raises(ValidationError):
            ConfigModel.model_validate(INVALID_PROVIDER_TYPE)

    def test_missing_provider_field(self) -> None:
        with pytest.raises(ValidationError, match="provider"):
            ConfigModel.model_validate(INVALID_MISSING_PROVIDER)

    def test_missing_default_model_field(self) -> None:
        with pytest.raises(ValidationError, match="default_model"):
            ConfigModel.model_validate(INVALID_MISSING_DEFAULT_MODEL_FIELD)

    def test_default_wrong_case(self) -> None:
        """Matching is case-sensitive: 'gpt-4o' != 'GPT-4o'."""
        with pytest.raises(ValidationError, match="Default model must be listed"):
            ConfigModel.model_validate(INVALID_DEFAULT_WRONG_CASE)


class TestConfigManagerIO:
    def test_missing_file_uses_default(self, tmp_path: Path) -> None:
        """No config.json on disk → falls back to DEFAULT_CONFIG without raising."""
        from aether_utils.config.constants import DEFAULT_CONFIG

        config_file = tmp_path / "config.json"  # deliberately not created

        with patch("aether_utils.config.config.get_config_file_path", return_value=config_file):
            manager = ConfigManager()

        assert manager.config.provider.type == DEFAULT_CONFIG.provider.type
        assert manager.config.provider.default_model == DEFAULT_CONFIG.provider.default_model

    def test_valid_file_is_loaded(self, tmp_path: Path) -> None:
        """A well-formed config.json is parsed and returned correctly."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(VALID_FULL), encoding="utf-8")

        with patch("aether_utils.config.config.get_config_file_path", return_value=config_file):
            manager = ConfigManager()

        assert manager.config.debug is True
        assert manager.config.provider.default_model == "GPT-4o"
        assert manager.config.subagents is not None
        assert manager.config.subagents.gatherer_model == "Claude Sonnet"

    def test_invalid_file_raises(self, tmp_path: Path) -> None:
        """A config.json that fails Pydantic validation raises ValidationError on load."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(INVALID_DEFAULT_IS_MODEL_ID), encoding="utf-8")

        with (
            patch("aether_utils.config.config.get_config_file_path", return_value=config_file),
            pytest.raises(ValidationError, match="Default model must be listed"),
        ):
            ConfigManager()

    def test_failed_write_does_not_update_config(self, tmp_path: Path) -> None:
        """If _write_config_file fails, the in-memory config must not be updated."""
        config_file = tmp_path / "config.json"

        with patch("aether_utils.config.config.get_config_file_path", return_value=config_file):
            manager = ConfigManager()

        original_config = manager.config

        with patch.object(manager, "_write_config_file", return_value=False):
            manager.config = VALID_FULL  # raw dict, as the setter now expects

        assert manager.config is original_config

    def test_setter_raises_on_invalid_dict(self, tmp_path: Path) -> None:
        """Setter validates before writing — invalid dict raises before touching disk."""
        config_file = tmp_path / "config.json"

        with patch("aether_utils.config.config.get_config_file_path", return_value=config_file):
            manager = ConfigManager()

        with pytest.raises(ValidationError, match="Default model must be listed"):
            manager.config = INVALID_DEFAULT_IS_MODEL_ID

        # config file should only contain the default, not the bad payload
        written = json.loads(config_file.read_text(encoding="utf-8"))
        assert written["provider"]["default_model"] == manager.config.provider.default_model

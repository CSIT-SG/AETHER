from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aether_benchmark.tasks.evaluate.evaluate import (
    CriterionResult,
    EvaluateTask,
    _build_prompt,
    _evaluate_criterion,
    _extract_addresses,
    _fetch_state,
)
from aether_rpc.capabilities.result import Ok
from agents import OpenAIChatCompletionsModel


@pytest.fixture
def model() -> OpenAIChatCompletionsModel:
    """A real model wrapper around a mock client — cheap, no network."""
    return OpenAIChatCompletionsModel(model="test-model", openai_client=MagicMock())


def _state() -> dict:
    return {
        "address": "0x4010A0",
        "function_name": "main",
        "pseudocode": "int main() { return 0; }",
        "local_variables": [{"name": "v1", "type": "int", "is_arg_var": False}],
        "call_tree": {
            "function_name": "main",
            "address": "0x4010A0",
            "children": [
                {"function_name": "sub_1234", "address": "0x401234", "children": []}
            ],
        },
    }


class TestExtractAddresses:
    @pytest.mark.parametrize(
        ("description", "expected"),
        [
            (
                "Evaluates packet headers at 0x4010A0 (Main Parser) and 0x4010B0 (Sub-Parser).",
                ["0x4010A0", "0x4010B0"],
            ),
            ("Covers the 0x4025C0 range.", ["0x4025C0"]),
            ("Applies to all transformation primitives in the 0x4010A0 range.", ["0x4010A0"]),
        ],
    )
    def test_finds_hex_addresses(self, description: str, expected: list[str]) -> None:
        assert _extract_addresses(description) == expected

    def test_no_addresses_returns_empty(self) -> None:
        assert _extract_addresses("General code maintainability requirements.") == []

    def test_empty_description(self) -> None:
        assert _extract_addresses("") == []


class TestFetchState:
    @patch("aether_benchmark.tasks.evaluate.evaluate.get_functions_called_recursively", new_callable=AsyncMock)
    @patch("aether_benchmark.tasks.evaluate.evaluate.get_local_variables", new_callable=AsyncMock)
    @patch("aether_benchmark.tasks.evaluate.evaluate.get_function_pseudocode", new_callable=AsyncMock)
    @patch("aether_benchmark.tasks.evaluate.evaluate.get_data_at_address", new_callable=AsyncMock)
    async def test_populates_state_from_rpc(
        self,
        mock_data: AsyncMock,
        mock_pseudo: AsyncMock,
        mock_locals: AsyncMock,
        mock_tree: AsyncMock,
    ) -> None:
        mock_data.return_value = Ok(result={"name": "main"})
        mock_pseudo.return_value = Ok(result={"pseudocode": "int main() { return 0; }"})
        mock_locals.return_value = Ok(
            result=[{"name": "v1", "type": "int", "is_arg_var": False}]
        )
        mock_tree.return_value = Ok(
            result={
                "root": {
                    "function_name": "main",
                    "address": "0x4010A0",
                    "children": [],
                }
            }
        )

        state = await _fetch_state(MagicMock(), "0x4010A0")

        assert state["function_name"] == "main"
        assert state["pseudocode"] == "int main() { return 0; }"
        assert state["local_variables"] == [{"name": "v1", "type": "int", "is_arg_var": False}]
        assert state["call_tree"] == {
            "function_name": "main",
            "address": "0x4010A0",
            "children": [],
        }

    @patch("aether_benchmark.tasks.evaluate.evaluate.get_data_at_address", new_callable=AsyncMock)
    async def test_graceful_when_name_lookup_fails(self, mock_data: AsyncMock) -> None:
        mock_data.side_effect = RuntimeError("rpc down")

        state = await _fetch_state(MagicMock(), "0x4010A0")

        assert state["function_name"] == "(unknown)"
        assert state["pseudocode"] == "(unavailable)"
        assert state["local_variables"] == []
        assert state["call_tree"] is None

    @patch("aether_benchmark.tasks.evaluate.evaluate.get_functions_called_recursively", new_callable=AsyncMock)
    @patch("aether_benchmark.tasks.evaluate.evaluate.get_local_variables", new_callable=AsyncMock)
    @patch("aether_benchmark.tasks.evaluate.evaluate.get_function_pseudocode", new_callable=AsyncMock)
    @patch("aether_benchmark.tasks.evaluate.evaluate.get_data_at_address", new_callable=AsyncMock)
    async def test_graceful_when_downstream_calls_fail(
        self,
        mock_data: AsyncMock,
        mock_pseudo: AsyncMock,
        mock_locals: AsyncMock,
        mock_tree: AsyncMock,
    ) -> None:
        """Name resolves, but every subsequent RPC call fails — state degrades."""
        mock_data.return_value = Ok(result={"name": "main"})
        mock_pseudo.side_effect = RuntimeError("decompile failed")
        mock_locals.side_effect = RuntimeError("locals failed")
        mock_tree.side_effect = RuntimeError("tree failed")

        state = await _fetch_state(MagicMock(), "0x4010A0")

        assert state["function_name"] == "main"
        assert state["pseudocode"] == "(unavailable)"
        assert state["local_variables"] == []
        assert state["call_tree"] is None


class TestBuildPrompt:
    def test_renders_rubric_name_and_state(self) -> None:
        prompt = _build_prompt(
            "Constants are replaced with named enums",
            [_state()],
            "packet_parsing_logic",
        )

        assert "packet_parsing_logic" in prompt
        assert "main" in prompt
        assert "0x4010A0" in prompt
        assert "int main() { return 0; }" in prompt
        assert "v1: int" in prompt

    def test_renders_multiple_states(self) -> None:
        state_a = _state()
        state_b = _state()
        state_b["address"] = "0x4010B0"
        state_b["function_name"] = "sub_parser"

        prompt = _build_prompt("text", [state_a, state_b], "rubric")

        assert "### Function 0x4010A0" in prompt
        assert "### Function 0x4010B0" in prompt
        assert "main" in prompt
        assert "sub_parser" in prompt

    def test_empty_states_fallback(self) -> None:
        prompt = _build_prompt("text", [], "rubric")

        assert "no target addresses found in description" in prompt


class TestEvaluateCriterion:
    @patch("aether_benchmark.tasks.evaluate.evaluate.force_structured_output", new_callable=AsyncMock)
    @patch("aether_benchmark.tasks.evaluate.evaluate.Runner.run", new_callable=AsyncMock)
    async def test_success(
        self, mock_run: AsyncMock, mock_force: AsyncMock, model: OpenAIChatCompletionsModel
    ) -> None:
        mock_run.return_value = MagicMock()
        mock_force.return_value = CriterionResult(
            description="Constants are replaced",
            passed=True,
            reasoning="The decompiled code shows enums.",
        )

        result = await _evaluate_criterion(
            "Constants are replaced", [_state()], "packet_parsing_logic", model
        )

        assert result["passed"] is True
        assert result["description"] == "Constants are replaced"
        assert result["reasoning"] == "The decompiled code shows enums."

    @patch("aether_benchmark.tasks.evaluate.evaluate.force_structured_output", new_callable=AsyncMock)
    @patch("aether_benchmark.tasks.evaluate.evaluate.Runner.run", new_callable=AsyncMock)
    async def test_structured_output_failure_returns_failed_result(
        self, mock_run: AsyncMock, mock_force: AsyncMock, model: OpenAIChatCompletionsModel
    ) -> None:
        mock_run.return_value = MagicMock()
        mock_force.side_effect = RuntimeError("model did not call submit_output")

        result = await _evaluate_criterion(
            "Constants are replaced", [_state()], "packet_parsing_logic", model
        )

        assert result["passed"] is False
        assert result["description"] == "Constants are replaced"
        assert "Evaluation failed" in result["reasoning"]


class TestEvaluateTask:
    @patch("aether_benchmark.tasks.evaluate.evaluate._evaluate_criterion", new_callable=AsyncMock)
    @patch("aether_benchmark.tasks.evaluate.evaluate._fetch_states", new_callable=AsyncMock)
    async def test_start_extracts_addresses_and_aggregates(
        self, mock_fetch: AsyncMock, mock_criterion: AsyncMock
    ) -> None:
        mock_fetch.return_value = [_state(), {**_state(), "address": "0x4010B0"}]
        mock_criterion.side_effect = [
            {"description": "c1", "passed": True, "reasoning": "ok"},
            {"description": "c2", "passed": True, "reasoning": "ok"},
        ]

        result = await EvaluateTask().start(
            {
                "name": "packet_parsing_logic",
                "description": "Evaluates packet headers at 0x4010A0 and 0x4010B0.",
                "criteria": ["c1", "c2"],
            },
            MagicMock(),
            {"api_key": "sk-test"},
        )

        assert result["rubric_name"] == "packet_parsing_logic"
        assert result["addresses"] == ["0x4010A0", "0x4010B0"]
        assert result["overall_passed"] is True
        assert len(result["results"]) == 2

    @patch("aether_benchmark.tasks.evaluate.evaluate._evaluate_criterion", new_callable=AsyncMock)
    @patch("aether_benchmark.tasks.evaluate.evaluate._fetch_states", new_callable=AsyncMock)
    async def test_start_overall_fails_when_any_criterion_fails(
        self, mock_fetch: AsyncMock, mock_criterion: AsyncMock
    ) -> None:
        mock_fetch.return_value = [_state()]
        mock_criterion.side_effect = [
            {"description": "c1", "passed": True, "reasoning": "ok"},
            {"description": "c2", "passed": False, "reasoning": "missing"},
        ]

        result = await EvaluateTask().start(
            {
                "name": "rubric_name",
                "description": "Targets 0x4010A0.",
                "criteria": ["c1", "c2"],
            },
            MagicMock(),
            {"api_key": "sk-test"},
        )

        assert result["overall_passed"] is False

    @patch("aether_benchmark.tasks.evaluate.evaluate._evaluate_criterion", new_callable=AsyncMock)
    @patch("aether_benchmark.tasks.evaluate.evaluate._fetch_states", new_callable=AsyncMock)
    async def test_start_no_addresses_in_description(
        self, mock_fetch: AsyncMock, mock_criterion: AsyncMock
    ) -> None:
        """Rubric without addresses — state fetch gets an empty list."""
        mock_fetch.return_value = []
        mock_criterion.side_effect = [
            {"description": "c1", "passed": True, "reasoning": "ok"}
        ]

        service = MagicMock()

        result = await EvaluateTask().start(
            {
                "name": "documentation_standards",
                "description": "General code maintainability requirements.",
                "criteria": ["c1"],
            },
            service,
            {"api_key": "sk-test"},
        )

        mock_fetch.assert_awaited_once_with(service, [])
        assert result["addresses"] == []
        assert result["overall_passed"] is True

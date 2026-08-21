from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aether_benchmark.tasks.evaluate.evaluate import (
    CriterionResult,
    EvaluateTask,
    _build_prompt,
    _evaluate_criterion,
    _extract_addresses,
)
from agents import OpenAIChatCompletionsModel


@pytest.fixture
def model() -> OpenAIChatCompletionsModel:
    """A real model wrapper around a mock client — cheap, no network."""
    return OpenAIChatCompletionsModel(model="test-model", openai_client=MagicMock())


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


class TestBuildPrompt:
    def test_renders_with_addresses(self) -> None:
        prompt = _build_prompt(
            "Constants are replaced with named enums",
            ["0x4010A0", "0x4010B0"],
            "packet_parsing_logic",
        )

        assert "packet_parsing_logic" in prompt
        assert "Constants are replaced" in prompt
        assert "0x4010A0, 0x4010B0" in prompt
        assert "available tools" in prompt

    def test_renders_without_addresses(self) -> None:
        prompt = _build_prompt("Test", [], "doc_standards")

        assert "doc_standards" in prompt
        assert "(no specific addresses)" in prompt


class TestEvaluateCriterion:
    @patch(
        "aether_benchmark.tasks.evaluate.evaluate.force_structured_output", new_callable=AsyncMock
    )
    @patch("aether_benchmark.tasks.evaluate.evaluate.Runner.run", new_callable=AsyncMock)
    async def test_success(
        self, mock_run: AsyncMock, mock_force: AsyncMock, model: OpenAIChatCompletionsModel
    ) -> None:
        mock_run.return_value = MagicMock()
        mock_force.return_value = CriterionResult(
            passed=True,
            reasoning="The decompiled code shows enums.",
        )

        result = await _evaluate_criterion(
            "Constants are replaced",
            ["0x4010A0"],
            "packet_parsing_logic",
            model,
            MagicMock(),
        )

        assert result["passed"] is True
        assert result["reasoning"] == "The decompiled code shows enums."

    @patch(
        "aether_benchmark.tasks.evaluate.evaluate.force_structured_output", new_callable=AsyncMock
    )
    @patch("aether_benchmark.tasks.evaluate.evaluate.Runner.run", new_callable=AsyncMock)
    async def test_structured_output_failure_returns_failed_result(
        self, mock_run: AsyncMock, mock_force: AsyncMock, model: OpenAIChatCompletionsModel
    ) -> None:
        mock_run.return_value = MagicMock()
        mock_force.side_effect = RuntimeError("model did not call submit_output")

        result = await _evaluate_criterion(
            "Constants are replaced",
            ["0x4010A0"],
            "packet_parsing_logic",
            model,
            MagicMock(),
        )

        assert result["passed"] is False
        assert "Evaluation failed" in result["reasoning"]

    @patch("aether_benchmark.tasks.evaluate.evaluate.Runner.run", new_callable=AsyncMock)
    async def test_agent_creates_subagent_tools(
        self, mock_run: AsyncMock, model: OpenAIChatCompletionsModel
    ) -> None:
        """Agent should be created with read-only forwarded_rpc tools."""
        mock_run.return_value = MagicMock()
        service = MagicMock()

        await _evaluate_criterion("test", ["0x4010A0"], "rubric", model, service)

        # Runner.run should have been called  at least once
        assert mock_run.await_count >= 1


@pytest.mark.asyncio
async def test_evaluate_task_start_aggregates_results() -> None:
    """End-to-end test of EvaluateTask.start orchestrating criteria."""

    with (
        patch(
            "aether_benchmark.tasks.evaluate.evaluate._evaluate_criterion", new_callable=AsyncMock
        ) as mock_criterion,
    ):
        mock_criterion.side_effect = [
            {"description": "c1", "passed": True, "reasoning": "ok"},
            {"description": "c2", "passed": False, "reasoning": "missing"},
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
        assert result["overall_passed"] is False
        assert len(result["results"]) == 2


@pytest.mark.asyncio
async def test_evaluate_task_no_addresses() -> None:
    """Rubric without addresses should still evaluate criteria."""

    with (
        patch(
            "aether_benchmark.tasks.evaluate.evaluate._evaluate_criterion", new_callable=AsyncMock
        ) as mock_criterion,
    ):
        mock_criterion.side_effect = [{"description": "c1", "passed": True, "reasoning": "ok"}]

        result = await EvaluateTask().start(
            {
                "name": "documentation_standards",
                "description": "General code maintainability requirements.",
                "criteria": ["c1"],
            },
            MagicMock(),
            {"api_key": "sk-test"},
        )

        assert result["addresses"] == []
        assert result["overall_passed"] is True


@pytest.mark.asyncio
async def test_evaluate_task_cancel() -> None:
    """cancel() should not raise."""
    task = EvaluateTask()
    await task.cancel()  # just must not raise

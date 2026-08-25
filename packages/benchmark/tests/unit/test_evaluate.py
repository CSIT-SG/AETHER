from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aether_benchmark.tasks.evaluate.evaluate import EvaluateTask
from aether_benchmark.tasks.evaluate.models import CriterionResult
from agents import OpenAIChatCompletionsModel


@pytest.fixture
def model() -> OpenAIChatCompletionsModel:
    """A real model wrapper around a mock client — cheap, no network."""
    return OpenAIChatCompletionsModel(model="test-model", openai_client=MagicMock())


@pytest.fixture
def task() -> EvaluateTask:
    return EvaluateTask()


class TestBuildPrompt:
    def test_includes_description_and_criterion(self) -> None:
        prompt = EvaluateTask._build_prompt(
            "Constants are replaced with named enums",
            "Evaluates packet headers at 0x4010A0 (Main Parser).",
            "packet_parsing_logic",
        )

        assert "packet_parsing_logic" in prompt
        assert "Constants are replaced" in prompt
        assert "0x4010A0" in prompt
        assert "available tools" in prompt


class TestEvaluateCriterion:
    @pytest.mark.asyncio
    @patch("aether_benchmark.tasks.evaluate.evaluate.EvaluateTask._SYSTEM_PROMPT", "system prompt")
    @patch(
        "aether_benchmark.tasks.evaluate.evaluate.force_structured_output", new_callable=AsyncMock
    )
    @patch("aether_benchmark.tasks.evaluate.evaluate.Runner.run", new_callable=AsyncMock)
    async def test_success(
        self,
        mock_run: AsyncMock,
        mock_force: AsyncMock,
        model: OpenAIChatCompletionsModel,
        task: EvaluateTask,
    ) -> None:
        mock_run.return_value = MagicMock()
        mock_force.return_value = CriterionResult(
            passed=True,
            reasoning="The decompiled code shows enums.",
        )

        result = await task._evaluate_criterion(
            "Constants are replaced",
            "Evaluates packet headers at 0x4010A0.",
            "packet_parsing_logic",
            model,
            MagicMock(),
        )

        assert result["passed"] is True
        assert result["reasoning"] == "The decompiled code shows enums."

    @pytest.mark.asyncio
    @patch("aether_benchmark.tasks.evaluate.evaluate.EvaluateTask._SYSTEM_PROMPT", "system prompt")
    @patch(
        "aether_benchmark.tasks.evaluate.evaluate.force_structured_output", new_callable=AsyncMock
    )
    @patch("aether_benchmark.tasks.evaluate.evaluate.Runner.run", new_callable=AsyncMock)
    async def test_structured_output_failure_returns_failed_result(
        self,
        mock_run: AsyncMock,
        mock_force: AsyncMock,
        model: OpenAIChatCompletionsModel,
        task: EvaluateTask,
    ) -> None:
        mock_run.return_value = MagicMock()
        mock_force.side_effect = RuntimeError("model did not call submit_output")

        result = await task._evaluate_criterion(
            "Constants are replaced",
            "Evaluates packet headers at 0x4010A0.",
            "packet_parsing_logic",
            model,
            MagicMock(),
        )

        assert result["passed"] is False
        assert "Evaluation failed" in result["reasoning"]

    @pytest.mark.asyncio
    @patch("aether_benchmark.tasks.evaluate.evaluate.EvaluateTask._SYSTEM_PROMPT", "system prompt")
    @patch("aether_benchmark.tasks.evaluate.evaluate.Runner.run", new_callable=AsyncMock)
    async def test_agent_creates_subagent_tools(
        self,
        mock_run: AsyncMock,
        model: OpenAIChatCompletionsModel,
        task: EvaluateTask,
    ) -> None:
        """Agent should be created with read-only forwarded_rpc tools."""
        mock_run.return_value = MagicMock()
        service = MagicMock()

        await task._evaluate_criterion("test", "desc", "rubric", model, service)

        # Runner.run should have been called at least once (may be more
        # if force_structured_output retries internally)
        assert mock_run.await_count >= 1


@pytest.mark.asyncio
async def test_evaluate_task_start_aggregates_results() -> None:
    """End-to-end test of EvaluateTask.start orchestrating criteria."""

    with (
        patch.object(EvaluateTask, "_evaluate_criterion", new_callable=AsyncMock) as mock_criterion,
    ):
        mock_criterion.side_effect = [
            {"passed": True, "reasoning": "ok"},
            {"passed": False, "reasoning": "missing"},
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
        assert result["overall_passed"] is False
        assert len(result["results"]) == 2


@pytest.mark.asyncio
async def test_evaluate_task_no_description() -> None:
    """Rubric without description should still evaluate criteria."""

    with (
        patch.object(EvaluateTask, "_evaluate_criterion", new_callable=AsyncMock) as mock_criterion,
    ):
        mock_criterion.side_effect = [{"passed": True, "reasoning": "ok"}]

        result = await EvaluateTask().start(
            {
                "name": "documentation_standards",
                "criteria": ["c1"],
            },
            MagicMock(),
            {"api_key": "sk-test"},
        )

        assert result["overall_passed"] is True


@pytest.mark.asyncio
async def test_evaluate_task_cancel() -> None:
    """cancel() should not raise."""
    task = EvaluateTask()
    await task.cancel()  # just must not raise

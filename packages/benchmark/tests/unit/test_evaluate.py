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
def adapter() -> MagicMock:
    """A mock EvidenceAdapter whose methods return benign values."""
    mock = MagicMock()
    mock.system_prompt = "system prompt"
    mock.build_tools.return_value = []
    mock.build_prompt.return_value = "grading prompt"
    mock.run_context.return_value = None
    return mock


@pytest.fixture
def task() -> EvaluateTask:
    return EvaluateTask()


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
            reasoning="The answer is correct.",
        )

        result = await task._evaluate_criterion(
            "Constants are replaced",
            "Evaluates packet headers at 0x4010A0.",
            "packet_parsing_logic",
            model,
            MagicMock(),
            adapter,
        )

        assert result["passed"] is True
        assert result["reasoning"] == "The answer is correct."

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
            adapter,
        )

        assert result["passed"] is False
        assert "Evaluation failed" in result["reasoning"]

    @pytest.mark.asyncio
    @patch("aether_benchmark.tasks.evaluate.evaluate.Runner.run", new_callable=AsyncMock)
    async def test_drives_through_adapter(
        self,
        mock_run: AsyncMock,
        model: OpenAIChatCompletionsModel,
        task: EvaluateTask,
        adapter: MagicMock,
    ) -> None:
        """Agent should be built from the adapter's tools/system prompt and run
        with the adapter's context + prompt."""
        mock_run.return_value = MagicMock()
        evidence = MagicMock()

        await task._evaluate_criterion("test", "desc", "rubric", model, evidence, adapter)

        adapter.build_tools.assert_called_once()
        adapter.build_prompt.assert_called_once()
        adapter.run_context.assert_called_once_with(evidence)
        assert mock_run.await_count >= 1


@pytest.mark.asyncio
async def test_evaluate_task_start_aggregates_results() -> None:
    """End-to-end test of EvaluateTask.start orchestrating criteria."""
    adapter = MagicMock()

    with patch.object(
        EvaluateTask, "_evaluate_criterion", new_callable=AsyncMock
    ) as mock_criterion:
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
            adapter,
        )

        assert result["rubric_name"] == "packet_parsing_logic"
        assert result["overall_passed"] is False
        assert len(result["results"]) == 2


@pytest.mark.asyncio
async def test_evaluate_task_no_description() -> None:
    """Rubric without description should still evaluate criteria."""
    adapter = MagicMock()

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
            adapter,
        )

        assert result["overall_passed"] is True


@pytest.mark.asyncio
async def test_evaluate_task_cancel() -> None:
    """cancel() should not raise."""
    task = EvaluateTask()
    await task.cancel()  # just must not raise


@pytest.mark.asyncio
async def test_evaluate_task_start_passes_adapter_to_criterion() -> None:
    """The adapter given to start must be forwarded to each criterion task."""
    adapter = MagicMock()

    with patch.object(
        EvaluateTask, "_evaluate_criterion", new_callable=AsyncMock
    ) as mock_criterion:
        mock_criterion.return_value = {"passed": True, "reasoning": "ok"}

        await EvaluateTask().start(
            {"name": "n", "criteria": ["c1", "c2"]},
            MagicMock(),
            {"api_key": "sk-test"},
            adapter,
        )

        for call in mock_criterion.call_args_list:
            assert call.args[-1] is adapter

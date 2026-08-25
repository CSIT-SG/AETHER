# type: ignore
from unittest.mock import AsyncMock, patch

import pytest
from aether_utils.compacting_session import CompactingSession
from agents import Agent
from agents.exceptions import ModelBehaviorError

RUNNER = "aether_utils.compacting_session.compacting_session.Runner.run"


def _session() -> CompactingSession:
    return CompactingSession(
        summarizer=Agent(name="s", instructions="summarize"), threshold=10, keep_last_n=5
    )


async def _fill(session: CompactingSession, items: int = 11) -> None:
    for i in range(items):
        await session.add_items([{"role": "user", "content": str(i)}])


def _result(final_output: str = "summary"):
    return type("R", (), {"final_output": final_output})()


@pytest.mark.asyncio
async def test_compaction_fires_over_threshold() -> None:
    session = _session()
    result = AsyncMock(return_value=_result())

    with patch(RUNNER, result):
        await _fill(session)

    history = await session.get_items()
    result.assert_called_once()
    assert len(history) == 6
    assert history[0]["role"] == "system"
    assert "summary" in history[0]["content"]


@pytest.mark.asyncio
async def test_a_failed_summarizer_is_retried_with_the_error() -> None:
    session = _session()
    flaky = AsyncMock(
        side_effect=[
            ModelBehaviorError("Tool execute_idapython not found in agent Compacting Agent"),
            _result(),
        ]
    )

    with patch(RUNNER, flaky):
        await _fill(session)

    assert flaky.await_count == 2
    assert "not found in agent" in flaky.await_args.kwargs["input"][-1]["content"]
    assert (await session.get_items())[0]["role"] == "system"


@pytest.mark.asyncio
async def test_compaction_that_produces_nothing_leaves_the_history_alone() -> None:
    for outcome in ({"side_effect": ModelBehaviorError("boom")}, {"return_value": _result("  ")}):
        session = _session()
        summarizer = AsyncMock(**outcome)

        with patch(RUNNER, summarizer):
            await _fill(session)

        assert len(await session.get_items()) == 11

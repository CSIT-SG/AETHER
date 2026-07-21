# type: ignore
from unittest.mock import AsyncMock, patch

import pytest
from aether_utils.compacting_session import CompactingSession
from agents import Agent


@pytest.mark.asyncio
async def test_compaction_fires_over_threshold() -> None:
    session = CompactingSession(
        summarizer=Agent(name="s", instructions="summarize"),
        threshold=10,
        keep_last_n=5,
    )
    result = AsyncMock(return_value=type("R", (), {"final_output": "summary"})())

    with patch("aether_utils.compacting_session.compacting_session.Runner.run", result):
        for i in range(11):
            await session.add_items([{"role": "user", "content": str(i)}])

    history = await session.get_items()
    result.assert_called_once()
    assert len(history) == 6
    print(history)
    assert history[0]["role"] == "system"
    assert "summary" in history[0]["content"]

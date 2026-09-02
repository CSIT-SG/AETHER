import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest
from aether_benchmark.cli import BenchmarkConfig, DocTarget
from aether_benchmark.tasks.evaluate import evaluate_idb, evaluate_md
from aether_benchmark.tasks.parse_benchmark.models import BenchmarkSchema, RubricEntry


class DummyAgent:
    def __init__(self, *args: object, **kwargs: object) -> None:
        pass


class DummyRunner:
    def __init__(
        self,
        *,
        agent: object,
        prompts: list[str],
        limit: int = 5,
        usage_hook: object | None = None,
    ) -> None:
        self.prompts = prompts

    async def run_all(
        self,
        *,
        context: object | None = None,
        max_turns: int = 20,
        run_config: object | None = None,
    ) -> list[dict[str, object]]:
        # return a success result per prompt
        return [
            {"success": True, "data": {"passed": True, "reasoning": "ok"}} for _ in self.prompts
        ]


def make_config() -> BenchmarkConfig:
    return BenchmarkConfig(
        target=DocTarget(doc=Path("doc.md")),
        rubric=Path("rubric.yml"),
        api_key="k",
        model="m",
        base_url="u",
        verbose=False,
        output=None,
    )


def test_evaluate_md_task_simple(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evaluate_md, "Agent", DummyAgent)
    monkeypatch.setattr(evaluate_md, "get_content", lambda *_a, **_k: "instr")
    monkeypatch.setattr(evaluate_md, "ParallelRunner", DummyRunner)

    task = evaluate_md.EvaluateMDTask()
    config = make_config()
    benchmark = BenchmarkSchema(name="b", rubrics=[RubricEntry(name="r", criteria=["c"])])

    out, tokens = asyncio.run(task.start(config, benchmark, "evidence"))

    assert out.rubrics[0].criteria[0].result["success"] is True
    assert tokens == 0


def test_evaluate_idb_task_simple(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evaluate_idb, "Agent", DummyAgent)
    monkeypatch.setattr(evaluate_idb, "get_content", lambda *_a, **_k: "instr")
    # avoid building real subagent tools
    monkeypatch.setattr(evaluate_idb, "build_subagent_tool", lambda _x=None: None)
    monkeypatch.setattr(evaluate_idb, "ParallelRunner", DummyRunner)

    task = evaluate_idb.EvaluateIDBTask()
    config = make_config()
    benchmark = BenchmarkSchema(name="b", rubrics=[RubricEntry(name="r", criteria=["c"])])

    # service can be a simple object since the runner ignores it, but provide a minimal stub
    class DummyService:
        def __getattr__(self, name: str) -> Callable[..., object]:
            def _stub(*_a: object, **_k: object) -> object:
                return None

            return _stub

    out, tokens = asyncio.run(
        task.start(service=DummyService(), config=config, benchmark=benchmark)
    )

    assert out.rubrics[0].criteria[0].result["success"] is True
    assert tokens == 0

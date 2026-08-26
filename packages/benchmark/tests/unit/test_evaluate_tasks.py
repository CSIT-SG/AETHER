import asyncio
from pathlib import Path

from aether_benchmark.cli import BenchmarkConfig, DocTarget
from aether_benchmark.tasks.evaluate import evaluate_idb, evaluate_md
from aether_benchmark.tasks.parse_benchmark.models import BenchmarkSchema, RubricEntry


class DummyAgent:
    def __init__(self, *args, **kwargs):
        pass


class DummyRunner:
    def __init__(self, *, agent, prompts, limit=5):
        self.prompts = prompts

    async def run_all(self, *, context=None, max_turns=20, run_config=None):
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
        json_output=False,
        output=None,
    )


def test_evaluate_md_task_simple(monkeypatch):
    monkeypatch.setattr(evaluate_md, "Agent", DummyAgent)
    monkeypatch.setattr(evaluate_md, "get_content", lambda *a, **k: "instr")
    monkeypatch.setattr(evaluate_md, "ParallelRunner", DummyRunner)

    task = evaluate_md.EvaluateMDTask()
    config = make_config()
    benchmark = BenchmarkSchema(name="b", rubrics=[RubricEntry(name="r", criteria=["c"])])

    out = asyncio.run(task.start(config, benchmark, "evidence"))

    assert out.rubrics[0].criteria[0].result["success"] is True


def test_evaluate_idb_task_simple(monkeypatch):
    monkeypatch.setattr(evaluate_idb, "Agent", DummyAgent)
    monkeypatch.setattr(evaluate_idb, "get_content", lambda *a, **k: "instr")
    # avoid building real subagent tools
    monkeypatch.setattr(evaluate_idb, "build_subagent_tool", lambda x: None)
    monkeypatch.setattr(evaluate_idb, "ParallelRunner", DummyRunner)

    task = evaluate_idb.EvaluateIDBTask()
    config = make_config()
    benchmark = BenchmarkSchema(name="b", rubrics=[RubricEntry(name="r", criteria=["c"])])

    # service can be a simple object since the runner ignores it
    out = asyncio.run(task.start(service=object(), config=config, benchmark=benchmark))  # type: ignore

    assert out.rubrics[0].criteria[0].result["success"] is True

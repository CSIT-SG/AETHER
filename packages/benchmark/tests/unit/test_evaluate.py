from aether_benchmark.tasks.evaluate.models import AgentRunResult, BenchmarkSchemaWithResults
from aether_benchmark.tasks.evaluate.utils import reconstruct_results
from aether_benchmark.tasks.parse_benchmark.models import BenchmarkSchema, RubricEntry


def test_reconstruct_results_basic() -> None:
    benchmark = BenchmarkSchema(
        name="b",
        version="1",
        rubrics=[
            RubricEntry(name="r1", criteria=["c1", "c2"]),
            RubricEntry(name="r2", criteria=["c3"]),
        ],
    )

    results: list[AgentRunResult] = [
        {"success": True, "data": {"passed": True, "reasoning": "ok"}},
        {"success": False, "error": "fail"},
        {"success": True, "data": {"passed": False, "reasoning": "no"}},
    ]

    out = reconstruct_results(benchmark, results)

    assert out.name == "b"
    assert len(out.rubrics) == 2
    assert out.rubrics[0].criteria[0].result["success"] is True
    assert out.rubrics[0].criteria[1].result["success"] is False
    assert out.rubrics[1].criteria[0].result["success"] is True


def test_reconstruct_results_insufficient_results_raises() -> None:
    benchmark = BenchmarkSchema(
        name="b",
        rubrics=[RubricEntry(name="r1", criteria=["c1", "c2"])],
    )

    results: list[AgentRunResult] = [{"success": True, "data": {"passed": True, "reasoning": "ok"}}]

    try:
        _ = reconstruct_results(benchmark, results)
        raised = False
    except Exception:
        raised = True

    assert raised


def test_benchmark_with_results_model_roundtrip() -> None:
    data = {
        "name": "b",
        "rubrics": [
            {
                "name": "r1",
                "criteria": [
                    {
                        "criterion": "c1",
                        "result": {"success": True, "data": {"passed": True, "reasoning": "ok"}},
                    }
                ],
            }
        ],
    }

    bm = BenchmarkSchemaWithResults(**data)
    assert bm.name == "b"
    assert bm.rubrics[0].criteria[0].criterion == "c1"

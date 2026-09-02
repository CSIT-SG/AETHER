import json

from aether_benchmark.cli import BenchmarkConfig
from aether_benchmark.tasks.evaluate.models import (
    BenchmarkSchemaWithResults,
    CriterionWithResult,
    RubricEntryWithResults,
)
from aether_benchmark.utils.task import Task
from rich.console import Console
from rich.highlighter import ReprHighlighter
from rich.tree import Tree


class PrintResultsTask(Task[[BenchmarkConfig, BenchmarkSchemaWithResults], None]):
    async def start(self, args: BenchmarkConfig, results: BenchmarkSchemaWithResults) -> None:
        """Print the results and write the JSON output."""
        console = Console()
        agg = self._aggregate(results)

        console.print(self._build_tree(args, results))
        console.print()
        console.print(f"Overall score: [bold]{agg['score']:.1%}[/bold]")
        console.print(
            f"[dim]({agg['passed']}/{agg['total']} passed)[/dim] "
            f"Weighted score: [bold]{agg['weighted_score']:.1%}[/bold]"
        )

        output = {
            "score": agg["score"],
            "weighted_score": agg["weighted_score"],
            "passed": agg["passed"],
            "total": agg["total"],
            **results.model_dump(),
        }
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")

    async def cancel(self) -> None:
        pass

    @staticmethod
    def _aggregate(results: BenchmarkSchemaWithResults) -> dict[str, float | int]:
        passed_flags = [PrintResultsTask._rubric_passed(r) for r in results.rubrics]
        weights = [r.weight for r in results.rubrics]
        total, passed, total_weight = len(passed_flags), sum(passed_flags), sum(weights)
        weighted_score = (
            sum(w for r, w in zip(passed_flags, weights, strict=True) if r) / total_weight
            if total_weight
            else 0.0
        )
        score = passed / total if total else 0.0
        return {"score": score, "passed": passed, "total": total, "weighted_score": weighted_score}

    @staticmethod
    def _rubric_passed(rubric: RubricEntryWithResults) -> bool:
        return all(
            c.result["success"] and "data" in c.result and c.result["data"]["passed"]
            for c in rubric.criteria
        )

    def _build_tree(self, args: BenchmarkConfig, results: BenchmarkSchemaWithResults) -> Tree:
        highlighter = ReprHighlighter()
        tree = Tree(
            f"[bold]{results.name} {f'v{results.version}' if results.version else ''}[/bold]"
        )
        for rubric in results.rubrics:
            ok = self._rubric_passed(rubric)
            color = "green" if ok else "red"
            mark = "✓" if ok else "✗"
            node = tree.add(f"[{color}][{mark}][/] [bold cyan]{rubric.name}[/bold cyan]")
            if args.verbose:
                for c in rubric.criteria:
                    node.add(self._build_criterion_node(c, highlighter))
        return tree

    def _build_criterion_node(self, c: CriterionWithResult, highlighter: ReprHighlighter) -> Tree:
        if c.result["success"]:
            assert "data" in c.result
            ok = c.result["data"]["passed"]
            status, reasoning = (
                ("[green]✓[/green]" if ok else "[red]✗[/red]"),
                c.result["data"]["reasoning"],
            )
        else:
            assert "error" in c.result
            status, reasoning = "[yellow]![/yellow]", f"Agent run failed: {c.result['error']}"

        node = Tree(f"[{status}] [bold]{c.criterion}[/bold]")
        text = highlighter(reasoning)
        text.stylize("dim")
        node.add(text)
        return node

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
        console = Console()
        rubric_passed_flags = [self._rubric_passed(rubric) for rubric in results.rubrics]
        weights = [rubric.weight for rubric in results.rubrics]
        agg = self._aggregate(rubric_passed_flags, weights)

        tree = self._build_tree(args, results, rubric_passed_flags)

        console.print(tree)
        console.print()
        console.print(
            f"Overall score: [bold]{agg['score']:.1%}[/bold] ({agg['passed']}/{agg['total']} passed)"
        )
        console.print(f"Weighted score: [bold]{agg['weighted_score']:.1%}[/bold]")

    async def cancel(self) -> None:
        pass

    def _aggregate(
        self,
        rubric_results: list[bool],
        weights: list[float],
    ) -> dict[str, float | int]:
        """Compute overall weighted score."""
        total = len(rubric_results)
        passed = sum(rubric_results)
        total_weight = sum(weights)
        weighted_score = (
            sum(w for r, w in zip(rubric_results, weights, strict=True) if r) / total_weight
            if total_weight > 0
            else 0.0
        )
        score = passed / total if total else 0.0
        return {"score": score, "passed": passed, "total": total, "weighted_score": weighted_score}

    def _rubric_passed(self, rubric: RubricEntryWithResults) -> bool:
        return all(
            c.result["success"] and "data" in c.result and c.result["data"]["passed"]
            for c in rubric.criteria
        )

    def _build_tree(
        self,
        args: BenchmarkConfig,
        results: BenchmarkSchemaWithResults,
        rubric_passed_flags: list[bool],
    ) -> Tree:
        highlighter = ReprHighlighter()
        tree = Tree(
            f"[bold]{results.name} {f'v{results.version}' if results.version else ''}[/bold]"
        )

        for rubric, rubric_passed in zip(results.rubrics, rubric_passed_flags, strict=True):
            status = "[green]✓[/green]" if rubric_passed else "[red]✗[/red]"
            rubric_node = tree.add(f"[{status}] [bold cyan]{rubric.name}[/bold cyan]")
            if not args.verbose:
                continue
            for c in rubric.criteria:
                rubric_node.add(self._build_criterion_node(c, highlighter))

        return tree

    def _build_criterion_node(self, c: CriterionWithResult, highlighter: ReprHighlighter) -> Tree:
        if c.result["success"]:
            assert "data" in c.result
            status = "[green]✓[/green]" if c.result["data"]["passed"] else "[red]✗[/red]"
            reasoning = c.result["data"]["reasoning"]
        else:
            assert "error" in c.result
            status = "[yellow]![/yellow]"
            reasoning = f"Agent run failed: {c.result['error']}"

        node = Tree(f"[{status}] [bold]{c.criterion}[/bold]")
        reasoning_text = highlighter(reasoning)
        reasoning_text.stylize("dim")
        node.add(reasoning_text)
        return node

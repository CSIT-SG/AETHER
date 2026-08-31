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
        passed_flags = [self._rubric_passed(r) for r in results.rubrics]
        weights = [r.weight for r in results.rubrics]
        total, passed, total_weight = len(passed_flags), sum(passed_flags), sum(weights)
        weighted_score = (
            sum(w for r, w in zip(passed_flags, weights, strict=True) if r) / total_weight
            if total_weight
            else 0.0
        )

        console.print(self._build_tree(args, results, passed_flags))
        console.print()
        console.print(
            f"Overall score: [bold]{passed / total if total else 0.0:.1%}[/bold] ({passed}/{total} passed)"
        )
        console.print(f"Weighted score: [bold]{weighted_score:.1%}[/bold]")

    async def cancel(self) -> None:
        pass

    def _rubric_passed(self, rubric: RubricEntryWithResults) -> bool:
        return all(
            c.result["success"] and "data" in c.result and c.result["data"]["passed"]
            for c in rubric.criteria
        )

    def _build_tree(
        self, args: BenchmarkConfig, results: BenchmarkSchemaWithResults, passed_flags: list[bool]
    ) -> Tree:
        highlighter = ReprHighlighter()
        tree = Tree(
            f"[bold]{results.name} {f'v{results.version}' if results.version else ''}[/bold]"
        )
        for rubric, ok in zip(results.rubrics, passed_flags, strict=True):
            node = tree.add(
                f"[{'green' if ok else 'red'}][{'✓' if ok else '✗'}][/] [bold cyan]{rubric.name}[/bold cyan]"
            )
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

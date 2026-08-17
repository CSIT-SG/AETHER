from typing import Any

from aether_benchmark.utils.task import Task


class EvaluateTask(Task[[dict[str, Any]], None]):  # type: ignore[misc]
    async def start(self, rubric: dict[str, Any]) -> None:
        # start the evaluation
        # for each criteria, make a new user prompt and submit it to the agent
        # collect the results and return them as a dictionary
        # use a typeddict please

        # use get_content from the utils package to get the system prompt
        pass

    async def cancel(self) -> None:
        # stop the evaluation
        pass

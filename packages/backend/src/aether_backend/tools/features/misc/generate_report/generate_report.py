from pathlib import Path
from typing import Any

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_functions_called_recursively,
    validate_yara_rule,
)
from aether_backend.utils.effect import Log, Program, Return
from aether_backend.utils.force_structured_output import force_structured_output
from aether_backend.utils.subagent import SubagentToolDependencies, build_subagent_tool
from aether_backend.utils.validation import HexAddress
from aether_utils.api_client import OpenAIGateway
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from agents import Agent, ModelSettings, Runner, RunResultStreaming

from .constants import MAX_VALIDATION_ATTEMPTS
from .types import GeneratedReport

SYSTEM_PROMPT = get_content(Path(__file__).parent, "generate_report_prompt.md")
config = get_config()


async def generate_report(service: Any, function_address: HexAddress) -> Program:
    agent = Agent(
        name="report_generator",
        model=OpenAIGateway().get_model(
            model_name=config.subagents.gatherer_model if config.subagents else None,
            feature="generate_report",
        ),
        instructions=SYSTEM_PROMPT,
        tools=list(
            map(
                build_subagent_tool,
                [
                    get_functions_called_recursively,
                    get_function_pseudocode,
                    get_data_at_address,
                    validate_yara_rule,
                ],
            )
        ),
        model_settings=ModelSettings(parallel_tool_calls=False),
    )
    deps = SubagentToolDependencies(service)

    result = Runner.run_streamed(
        agent,
        context=deps,
        input=f"Generate a full analysis report with YARA rules for the function at "
        f"{function_address}.",
        max_turns=1000,
    )
    async for log in _stream_logs(result):
        yield log

    print(result.final_output)

    # Gateway bug means output_type isn't reliable; nudge for a forced
    # submit_output call if the model didn't already emit one in the stream.
    report: GeneratedReport = await force_structured_output(agent, GeneratedReport, result)

    rules, report_text = report["yara_rules"], report["report"]

    for attempt in range(MAX_VALIDATION_ATTEMPTS):
        failed = []
        for rule in rules:
            validation_result = await validate_yara_rule(service, rule_text=rule)
            if not validation_result.success:
                failed.append({"rule": rule, "error": validation_result})
        if not failed:
            break

        yield Log(
            f"{len(failed)} rule(s) failed validation (attempt {attempt + 1}); regenerating..."
        )

        result = Runner.run_streamed(
            agent,
            context=deps,
            input=result.to_input_list()
            + [
                {
                    "role": "user",
                    "content": f"These YARA rules failed validation: {failed}. Fix them and "
                    f"resubmit only the rules with the complete corrected list of all YARA rules.",
                }
            ],
            max_turns=1000,
        )
        async for log in _stream_logs(result):
            yield log
        rules = await force_structured_output(agent, list[str], result)
    else:
        yield Log("Max validation attempts reached; returning last draft despite failures.")

    yield Return(
        {
            "report": report_text,
            "yara_rules": rules,
        }
    )


async def _stream_logs(result: RunResultStreaming) -> Program:
    async for event in result.stream_events():
        if event.type != "run_item_stream_event":
            continue
        item = event.item
        if item.type == "tool_call_item":
            yield Log(f"{item.tool_name}({getattr(item.raw_item, 'arguments', '')})")
        elif item.type == "tool_call_output_item":
            yield Log(str(item.output))

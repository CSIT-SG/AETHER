from __future__ import annotations

from .runtime import MultiAgentRuntime
from .runtime.agent import CallbackAgent
from .tools import FunctionTool


def build_demo_runtime() -> MultiAgentRuntime:
    runtime = MultiAgentRuntime()

    def format_findings(ctx, findings: list[str]) -> str:
        return "\n".join(f"- {item}" for item in findings)

    def planner(agent, message, ctx):
        planning = ctx.tools["planning"]
        context = ctx.tools["context"]

        if message.topic == "start":
            planning.create_plan(
                ctx,
                goal="Coordinate research and reporting",
                actions=[
                    {"description": "Ask researcher for findings"},
                    {"description": "Send findings to reporter"},
                ],
            )
            ask_id = ctx.plan_manager.active_plan.actions[0].id
            send_id = ctx.plan_manager.active_plan.actions[1].id
            context.set(ctx, "ask_findings_action_id", ask_id)
            context.set(ctx, "send_report_action_id", send_id)
            planning.update_plan(ctx, start_action_ids=[ask_id])
            context.set(ctx, "sample_name", "demo-sample")
            ctx.send(
                "researcher",
                "Analyze the sample and return the top behavioral risks.",
                topic="research",
            )
        elif message.topic == "research_reply":
            ask_id = context.get(ctx, "ask_findings_action_id")
            send_id = context.get(ctx, "send_report_action_id")
            planning.update_plan(ctx, complete_actions=[{"action_id": ask_id, "result": "Findings received from researcher"}])
            planning.update_plan(ctx, start_action_ids=[send_id])
            ctx.send(
                "reporter",
                message.content,
                topic="draft_report",
            )

    def researcher(agent, message, ctx):
        if message.topic == "research":
            findings = [
                "The sample reads sensitive credentials from disk.",
                "The sample persists through registry autorun keys.",
                "The sample prepares outbound C2-style network traffic.",
            ]
            for finding in findings:
                ctx.memory_store.add_memory(key=finding, value=finding, category="runtime")
            ctx.reply(message, findings, topic="research_reply")

    def reporter(agent, message, ctx):
        if message.topic == "draft_report":
            formatter = ctx.tools["formatter"]
            rendered = formatter.invoke(ctx, message.content)
            ctx.publish("final_report", f"Collaboration result:\n{rendered}")

    runtime.add_agent(CallbackAgent("planner", planner, description="Coordinates work"))
    runtime.add_agent(CallbackAgent("researcher", researcher, description="Produces findings"))
    runtime.add_agent(
        CallbackAgent(
            "reporter",
            reporter,
            description="Publishes final output",
            tools=[FunctionTool("formatter", format_findings, description="Formats findings into bullet points")],
        )
    )
    runtime.send("system", "planner", "Begin the workflow", topic="start")
    return runtime


def main() -> None:
    runtime = build_demo_runtime()
    runtime.run()
    print(runtime.shared_state["final_report"])


if __name__ == "__main__":
    main()

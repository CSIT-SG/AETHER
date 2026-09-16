from pathlib import Path
from typing import Any, Literal

import ida_funcs
import ida_kernwin
from aether_gui.runner import get_shared_worker_manager
from aether_gui.utils.mcp import CallToolTask, MCPClient
from aether_gui.utils.rpc_id import get_rpc_id
from aether_gui.utils.ui import deserialise_call_tool_result
from aether_utils.logger import get_logger

logger = get_logger("generate_report_handler")


class GenerateReportHandler(ida_kernwin.action_handler_t):
    def __init__(self, mcp_client: MCPClient) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self.mcp_client = mcp_client

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:
        worker_manager = get_shared_worker_manager()
        rpc_id = get_rpc_id()
        screen_ea = ida_kernwin.get_screen_ea()
        ea = ida_funcs.get_func(screen_ea).start_ea
        func_name = ida_funcs.get_func_name(ea)

        task = CallToolTask()
        handle = worker_manager.submit(
            task,
            mcp_client=self.mcp_client,
            tool_name="generate_report_tool",
            tool_args={"rpc_id": rpc_id, "function_name": func_name},
        )

        worker_manager.consume(
            handle=handle,
            on_event=lambda result: self.save_wrapper(
                deserialise_call_tool_result(result), func_name
            ),
        )

        return 0

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> Any:
        return int(ida_kernwin.AST_ENABLE_ALWAYS)

    def save_wrapper(self, content: str, func_name: str) -> None:
        def save_markdown_report() -> bool:
            """Prompt the user for a path and save the given content as a Markdown file."""
            path_str: str | None = ida_kernwin.ask_file(
                True, f"{func_name}.md", "Markdown files|*.md|All files|*.*"
            )
            if path_str is None:
                print("User cancelled the save dialog")
                return False

            path: Path = Path(path_str)
            # IDA's dialog won't auto-append the extension, so enforce it if you want
            if path.suffix.lower() != ".md":
                path = path.with_suffix(".md")

            path.write_text(content, encoding="utf-8")
            print(f"Saved report to {path}")
            return True

        ida_kernwin.execute_sync(save_markdown_report, ida_kernwin.MFF_WRITE)

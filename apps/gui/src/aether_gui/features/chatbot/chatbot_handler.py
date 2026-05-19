from typing import Any, Literal

import ida_kernwin
from aether_gui.features.chatbot.ui.main_window import MainWindow


class ChatbotHandler(ida_kernwin.action_handler_t):
    def __init__(self) -> None:
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:
        target_title = "Pseudocode-A"
        target_widget = ida_kernwin.find_widget(target_title)

        if not target_widget:
            print(f"[AETHER] Error: Cleanly attach failed. Make sure '{target_title}' is open.")
            return 0

        # 2. Instantiate our custom PluginForm
        panel = MainWindow()

        # 3. Create the widget container inside IDA
        # Flags define its window style (WOPN_DP_RIGHT means dock it positionally to the right)
        panel.Show(
            "AETHER Insights",
            options=ida_kernwin.PluginForm.WOPN_DP_RIGHT | ida_kernwin.PluginForm.WOPN_RESTORE
        )

        # 4. Grab our newly created widget reference from IDA's window manager
        new_widget = ida_kernwin.find_widget("AETHER Insights")

        if new_widget and target_widget:
            # 5. This command forces IDA to slice the layout and group them together!
            # Arguments: (SourceWidget, DestinationWidget, DockPosition)
            ida_kernwin.set_dock_pos(
                "AETHER Insights",
                target_title,
                ida_kernwin.DP_RIGHT
            )

        return 0

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> Any:
        return int(ida_kernwin.AST_ENABLE_ALWAYS)

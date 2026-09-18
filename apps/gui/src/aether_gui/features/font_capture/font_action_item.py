# font_action_item.py
from dataclasses import dataclass

import ida_kernwin


@dataclass
class FontActionItem:
    action_name: str
    handler: ida_kernwin.action_handler_t | None

    def to_action_desc(self) -> ida_kernwin.action_desc_t:
        return ida_kernwin.action_desc_t(
            self.action_name,
            self.action_name,
            self.handler,
            "",
            "",
            -1,
        )

    def register(self) -> None:
        state = ida_kernwin.get_action_state(self.action_name)
        if state is None or not state[0]:
            ida_kernwin.register_action(self.to_action_desc())

    def unregister(self) -> None:
        ida_kernwin.unregister_action(self.action_name)
        self.handler = None

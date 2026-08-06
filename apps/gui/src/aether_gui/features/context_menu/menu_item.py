from __future__ import annotations

from dataclasses import dataclass, field

import ida_kernwin

from .constants import MENU_PATH


@dataclass
class ContextMenuItem:
    action_name: str = ""
    label: str = ""
    handler: ida_kernwin.action_handler_t | None = None
    hotkey: str = ""
    tooltip: str = ""
    children: list[ContextMenuItem] = field(default_factory=list)

    @property
    def is_leaf(self) -> bool:
        return self.handler is not None

    def to_action_desc(self) -> ida_kernwin.action_desc_t:
        return ida_kernwin.action_desc_t(
            self.action_name, self.label, self.handler, self.hotkey, self.tooltip, -1
        )

    def register(self) -> None:
        if self.is_leaf and not ida_kernwin.get_action_state(self.action_name)[0]:
            ida_kernwin.register_action(self.to_action_desc())
        for child in self.children:
            child.register()

    def attach_to_popup(self, widget, popup, path: str = MENU_PATH) -> None:
        if self.is_leaf:
            ida_kernwin.attach_action_to_popup(widget, popup, self.action_name, path)
            return
        child_path = f"{path}{self.label}/"
        for child in self.children:
            child.attach_to_popup(widget, popup, child_path)

    def unregister(self) -> None:
        if self.is_leaf:
            ida_kernwin.unregister_action(self.action_name)
            self.handler = None
        for child in self.children:
            child.unregister()

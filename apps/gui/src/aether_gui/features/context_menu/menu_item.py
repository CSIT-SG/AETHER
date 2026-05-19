from dataclasses import dataclass

import ida_kernwin


@dataclass
class ContextMenuItem:
    action_name: str
    label: str
    handler: ida_kernwin.action_handler_t
    hotkey: str = ""
    tooltip: str = ""
    submenu: str | None = None

    def to_action_desc(self) -> ida_kernwin.action_desc_t:
        return ida_kernwin.action_desc_t(
            self.action_name, self.label, self.handler, self.hotkey, self.tooltip, -1
        )

    def register(self) -> None:
        if not ida_kernwin.get_action_state(self.action_name)[0]:
            ida_kernwin.register_action(self.to_action_desc())

    def attach_to_popup(self, widget, popup, default_menu_path: str = "aether-next/") -> None:
        path = self.submenu or default_menu_path
        ida_kernwin.attach_action_to_popup(widget, popup, self.action_name, path)

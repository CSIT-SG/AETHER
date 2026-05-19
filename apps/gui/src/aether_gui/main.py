import json

import idaapi
from aether_core.config import load_config
from aether_utils.logger import get_logger

from aether_gui.features.context_menu import AetherUIHooks

logger = get_logger("gui")
_ui_hooks: AetherUIHooks | None = None


class _Aether(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = wanted_name = "Aether"
    help = wanted_hotkey = ""

    def init(self) -> int:
        global _ui_hooks
        logger = get_logger("ida_plugin")
        logger.info("IDA plugin initialized")
        cfg = load_config()
        logger.info("Config loaded: %s", json.dumps(cfg.model_dump(), indent=2))

        if _ui_hooks is None:
            _ui_hooks = AetherUIHooks()
            _ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg) -> None:
        pass

    def term(self) -> None:
        global _ui_hooks
        if _ui_hooks is not None:
            try:
                _ui_hooks.unhook()
            except Exception as e:
                logger.warning("Failed to unhook AETHER UI hooks: %s", e)
            finally:
                _ui_hooks = None


def PLUGIN_ENTRY() -> _Aether:
    return _Aether()

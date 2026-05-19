import json

import idaapi
from aether_core.config import load_config
from aether_utils.logger import get_logger

from aether_gui.features.context_menu import hook as _hook_ui
from aether_gui.features.context_menu import unhook as _unhook_ui

logger = get_logger("gui")


class _Aether(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = wanted_name = "Aether"
    help = wanted_hotkey = ""

    def init(self) -> int:
        logger = get_logger("ida_plugin")
        logger.info("IDA plugin initialized")
        cfg = load_config()
        logger.info("Config loaded: %s", json.dumps(cfg.model_dump(), indent=2))
        _hook_ui()
        return idaapi.PLUGIN_KEEP

    def run(self, arg) -> None:
        pass

    def term(self) -> None:
        _unhook_ui()


def PLUGIN_ENTRY() -> _Aether:
    return _Aether()

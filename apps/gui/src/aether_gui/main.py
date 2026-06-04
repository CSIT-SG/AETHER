import json

import idaapi
from aether_core.config import load_config
from aether_utils.logger import get_logger

from aether_gui.features.context_menu import AetherUIHooks
from aether_utils.is_headless_ida import is_headless_ida

logger = get_logger("gui_plugin")


class _Aether(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_UNL
    comment = wanted_name = "Aether"
    help = wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        # Keep the state bound to the instance, completely avoiding 'global'
        self._ui_hooks: AetherUIHooks | None = None

    def init(self) -> int:
        if is_headless_ida():
            logger.debug("Headless IDA detected, skipping GUI plugin initialization")
            return idaapi.PLUGIN_SKIP
        
        logger.debug("GUI plugin initialized")

        try:
            cfg = load_config()
            logger.info("Config loaded: %s", json.dumps(cfg.model_dump(), indent=2))
        except Exception as e:
            logger.error("Failed to load config: %s", e)

        # Initialize and hook into IDA using the instance memory space
        if self._ui_hooks is None:
            self._ui_hooks = AetherUIHooks()
            self._ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg) -> None:
        pass

    def term(self) -> None:
        # No global lookups. This object is guaranteed to exist right here.
        if self._ui_hooks is not None:
            try:
                self._ui_hooks.unregister()
                self._ui_hooks.unhook()
                logger.info("AETHER UI hooks cleanly unhooked.")
            except Exception as e:
                logger.warning("Failed to unhook AETHER UI hooks: %s", e)
            finally:
                self._ui_hooks = None


def PLUGIN_ENTRY() -> _Aether:
    return _Aether()

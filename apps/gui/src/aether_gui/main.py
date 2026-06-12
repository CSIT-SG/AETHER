import json

import ida_nalt
import idaapi
from aether_rpc.gui_server import GUIRPCServer
from aether_utils.config import get_config_manager
from aether_utils.file_id import file_id
from aether_utils.is_headless_ida import is_headless_ida
from aether_utils.logger import get_logger

from aether_gui.features.context_menu import AetherUIHooks

logger = get_logger("gui_plugin")


class _Aether(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_UNL
    comment = wanted_name = "Aether"
    help = wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        # Keep the state bound to the instance, completely avoiding 'global'
        self._ui_hooks: AetherUIHooks | None = None

        self._rpc_server = GUIRPCServer(file_id=file_id(ida_nalt.get_input_file_path()))

    def init(self) -> int:
        if is_headless_ida():
            logger.debug("Headless IDA detected, skipping GUI plugin initialization")
            return idaapi.PLUGIN_SKIP

        logger.debug("GUI plugin initialized")

        try:
            cfg = get_config_manager().config
            logger.info("Config loaded: %s", json.dumps(cfg.model_dump(), indent=2))
        except Exception as e:
            logger.error("Failed to load config: %s", e)

        # Initialize and hook into IDA using the instance memory space
        if self._ui_hooks is None:
            self._ui_hooks = AetherUIHooks()
            self._ui_hooks.hook()

        self._rpc_server.start()

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
        self._rpc_server.stop()


def PLUGIN_ENTRY() -> _Aether:
    return _Aether()

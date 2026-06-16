import json

import ida_nalt
import idaapi
from aether_rpc.gui_server import GUIRPCServer
from aether_utils.config import get_config
from aether_utils.file_id import file_id
from aether_utils.is_headless_ida import is_headless_ida
from aether_utils.logger import get_logger

from aether_gui.features.context_menu import AetherUIHooks
<<<<<<< HEAD
=======
from aether_gui.features.settings_menu import SettingsMenuHandler  #, SettingsMenuEntrypoint
>>>>>>> b3c769a (feat(settings_menu): shit appears now lol)

logger = get_logger("gui_plugin")


class _Aether(idaapi.plugin_t):
<<<<<<< HEAD
    flags = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_UNL
    comment = wanted_name = "Aether"
    help = wanted_hotkey = ""
=======
    flags = idaapi.PLUGIN_KEEP
    comment = "Settings Menu"
    help = ""
    wanted_name = "Aether_Config"
    wanted_hotkey = ""
>>>>>>> b3c769a (feat(settings_menu): shit appears now lol)

    def __init__(self):
        super().__init__()
        self._ui_hooks = None
        self._rpc_server = None
        self._settings_handler = None

    def init(self) -> int:
        if is_headless_ida():
            logger.debug("Headless IDA detected, skipping GUI plugin initialization")
            return idaapi.PLUGIN_SKIP

        path = ida_nalt.get_input_file_path()
        if not path:
            logger.warning("No input file path available yet")
            return idaapi.PLUGIN_SKIP

        self._rpc_server = GUIRPCServer(file_id=file_id(path))

        try:
            cfg = get_config()
            logger.info("Config loaded: %s", json.dumps(cfg.model_dump(), indent=2))
        except Exception as e:
            logger.error("Failed to load config: %s", e)

        # Initialize and hook into IDA using the instance memory space
        if self._ui_hooks is None:
            self._ui_hooks = AetherUIHooks()
            self._ui_hooks.hook()

        self._rpc_server.start()
<<<<<<< HEAD

=======
>>>>>>> b3c769a (feat(settings_menu): shit appears now lol)
        return idaapi.PLUGIN_KEEP

    def run(self, arg) -> None:
        dialog = SettingsMenuHandler()
        dialog.exec()

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
        if self._rpc_server:
            self._rpc_server.stop()
<<<<<<< HEAD
=======
        ida_kernwin.detach_action_from_menu("Edit/Plugins/", ACTION_NAME)
        ida_kernwin.unregister_action(ACTION_NAME)
>>>>>>> b3c769a (feat(settings_menu): shit appears now lol)


def PLUGIN_ENTRY() -> _Aether:
    return _Aether()

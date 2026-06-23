import ida_funcs
import ida_kernwin
import idaapi

from ainalyse import load_config, run_async_in_ida, validate_basic_config
from ainalyse.async_manager import use_async_worker, start_pipeline
from ainalyse.utils import prepare_activate_context

from .deobfuscator import run_deobfuscator

from .viewer import show_or_update_ai_deobfs_tab

class UnflattenerHandler(ida_kernwin.action_handler_t):
    is_running = False
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if UnflattenerHandler.is_running:
            print("[AETHER] [Unflatten] Unflattener is already running...")
            return 1

        try:
            def _update_unflatten_config(config):
                config["SINGLE_ANALYSIS_MODEL"] = config.get("SINGLE_ANALYSIS_MODEL") or config.get("OPENAI_MODEL")

            config, current_func_addr, current_func_name = prepare_activate_context(
                load_config,
                validate_basic_config,
                _update_unflatten_config,
            )
            if not config:
                return 1
            
            print("[AInalyse] [Unflatten] Generating unflattener results...")

            @use_async_worker("Unflatten")
            async def unflatten_thread(config, current_func_name, current_func_addr):
                try:
                    show_or_update_ai_deobfs_tab(current_func_addr)
                    success = await run_deobfuscator(config, current_func_name, current_func_addr)
                    if not success:
                        print("[AInalyse] [Unflatten] Unflattener analysis failed.")
                except Exception as e:
                    print(f"[AInalyse] [Unflatten] Error running unflatten: {e}")
                    import traceback
                    traceback.print_exc()
                finally:
                    UnflattenerHandler.is_running = False
            UnflattenerHandler.is_running = True
            if start_pipeline(unflatten_thread(config, current_func_name, current_func_addr)) is False:
                print(f"[AETHER] [Unflatten] Error running unflatten: Another function is currently being executed")
                UnflattenerHandler.is_running = False
        except Exception as e:
            print(f"[AInalyse] [Unflatten] Error running unflatten: {e}")
            UnflattenerHandler.is_running = False
            import traceback
            traceback.print_exc()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET
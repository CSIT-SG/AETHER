import asyncio
import time

import ida_funcs
import ida_kernwin
import idaapi

from ainalyse.async_manager import use_async_worker, start_pipeline
from ainalyse.utils import prepare_activate_context, refresh_functions

class QuickAnalyseHandler(ida_kernwin.action_handler_t):
    is_running = False
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if QuickAnalyseHandler.is_running:
            return 1
        QuickAnalyseHandler.is_running = True

        try:
            # Import here to avoid circular imports
            from . import (
                add_analysis_entry,
                load_config,
                validate_analysis_config,
                validate_basic_config,
            )
            from .annotator import run_annotator_agent
            from .function_selection import collect_functions_with_default_criteria
            from .gatherer import run_gatherer_agent
            from .manual_gatherer import run_manual_gatherer_agent

            def _update_quick_config(config):
                config["ANNOTATOR_MODEL"] = config.get("ANNOTATOR_MODEL") or config.get("OPENAI_MODEL")
                config["custom_user_prompt"] = ""
                config["fast_mode"] = True  # Enable fast mode by default for quick analysis

            config, current_func_addr, current_func_name = prepare_activate_context(
                load_config,
                validate_basic_config,
                _update_quick_config,
            )
            if not config:
                QuickAnalyseHandler.is_running = False
                return 1
            
            print("[AETHER] Starting quick analysis with default selection...")

            @use_async_worker("QuickAnalysis")
            async def quick_analysis_thread(config, current_func_addr, current_func_name):
                try:
                    # Validate configuration first
                    validation_success, validation_msg = await validate_analysis_config(config)
                    if not validation_success:
                        ida_kernwin.execute_sync(lambda: ida_kernwin.warning(f"Config failed:\n{validation_msg}"), ida_kernwin.MFF_WRITE)
                        return
                    
                    print(f"[AETHER] Quick analysis starting from function: {current_func_name}")
                    
                    # Use the shared function collection utility with proper container pattern
                    selected_functions_container = {"functions": []}
                    
                    def _collect_functions_sync():
                        try:
                            result = collect_functions_with_default_criteria(
                                current_func_addr, current_func_name, 
                                depth=0, max_depth=5
                            )
                            selected_functions_container["functions"] = result
                            return len(result)  # Return count for execute_sync
                        except Exception as e:
                            print(f"[AETHER] [Quick] Error in function collection: {e}")
                            selected_functions_container["functions"] = []
                            return 0
                    
                    # Execute the collection and get the result from container
                    ida_kernwin.execute_sync(_collect_functions_sync, ida_kernwin.MFF_READ)
                    selected_functions = selected_functions_container["functions"]
                    
                    print(f"[AETHER] [Quick] Automatically selected {len(selected_functions)} functions using default criteria")
                    
                    if len(selected_functions) <= 1:
                        print("[AETHER] [Quick] No additional functions selected, falling back to standard gatherer")
                        gatherer_success, starting_function, gatherer_output = await run_gatherer_agent(config)
                    else:
                        # Use manual gatherer with auto-selected functions
                        config["manual_functions"] = selected_functions
                        gatherer_success, starting_function, gatherer_output = await run_manual_gatherer_agent(config)
                    
                    annotator_output = ""
                    if gatherer_success:
                        print("[AETHER] Gatherer completed successfully. Waiting 3 seconds before starting annotator...")
                        await asyncio.sleep(3)
                        annotator_result, annotator_llm_output = await run_annotator_agent(config)
                        if annotator_result:
                            annotator_output = annotator_llm_output
                            refresh_functions(selected_functions, current_func_addr, log_prefix="[AETHER] [Quick]")
                            ida_kernwin.execute_sync(lambda: add_analysis_entry(gatherer_output, annotator_output, starting_function or current_func_name), ida_kernwin.MFF_WRITE)
                    else:
                        print("[AETHER] Gatherer failed or did not complete. Skipping annotator.")
                except Exception as e:
                    print(f"[AETHER] Error running AETHER: {e}")
                    import traceback
                    traceback.print_exc()
                finally:
                    QuickAnalyseHandler.is_running = False
                print("[AETHER] Done.")

            start_pipeline(quick_analysis_thread(config, current_func_addr, current_func_name))
        except Exception as e:
            print(f"[AETHER] Error running AETHER: {e}")
            import traceback
            traceback.print_exc()
            QuickAnalyseHandler.is_running = False
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

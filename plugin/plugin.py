import os
import time
import traceback
import socket

import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_loader
import idaapi
import idautils

# --- Import shared functions from ainalyse package ---
from ainalyse import (
    CONFIG_FILE,
    add_analysis_entry,
    create_default_config,
    get_current_function_name,
    load_config,
    load_custom_prompts,
    read_analysis_history,
    save_config,
    save_custom_prompts,
    show_config_error,
    validate_analysis_config,
    validate_basic_config,  # Add the new validation function
    write_analysis_history,
)
from ainalyse.ai_decomp import (
    AI_DECOMP_VIEW_TITLE,
    AIDecompHandler,
    AIDecompHandlerB,
    AIDecompSelectorHandler,
    ClearAIDecompHandler,
    install_ai_decomp_hooks,
    remove_ai_decomp_hooks,
)
from ainalyse.annotator import run_annotator_agent
from ainalyse.async_manager import ASYNC_WORKER, run_async_in_ida, run_in_background
from ainalyse.chatbot.viewer import show_chatbot_viewer

# --- Dialog imports ---
from ainalyse.function_selection import (
    FunctionSelectionDialog,  # Use shared dialog instead of ManualGathererDialog
    collect_functions_with_default_criteria,
)
from ainalyse.gatherer import call_openai_llm_gatherer, run_gatherer_agent

# --- AETHER specific imports ---
from ainalyse.manual_gatherer import run_manual_gatherer_agent
from ainalyse.quick_analyse import QuickAnalyseHandler
from ainalyse.realtime.handlers import CustomPromptReAnnotateHandler, FastLookHandler, StripAIAnnotationsHandler
from ainalyse.undo_retry import undo_analysis_annotations

from ainalyse.struct_creator.handler import StructCreationHandler as StructRefactorHandler

from PyQt5 import QtCore, QtWidgets

# --- Output File Paths ---
CTX_FILE_PATH = os.path.join(os.path.dirname(__file__), "ainalyse", "ctx.txt")
VERBOSE_LOG_PATH = os.path.join(os.path.dirname(__file__), "ainalyse", "verbose.txt")

# --- Action Handlers ---
class ChatbotHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        widget_title = ida_kernwin.get_widget_title(ctx.widget)
        show_chatbot_viewer(dock_target=widget_title)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

def check_config_and_show_error_if_invalid(config: dict) -> bool:
    """Common function to check config and show error dialog if invalid."""
    if not os.path.exists(CONFIG_FILE):
        create_default_config()
        show_config_error()
        return False

    # Perform basic validation
    is_valid, error_msg = validate_basic_config(config)
    if not is_valid:
        ida_kernwin.warning(error_msg)
        return False

    return True

class AdvancedAnalyseHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        current_func = get_current_function_name()
        base_config = load_config()

        # Use common validation function
        if not check_config_and_show_error_if_invalid(base_config):
            return 1

        gatherer_prompt, annotator_prompt = load_custom_prompts()

        from ainalyse.dialogs_ida import AdvancedOptionsDialog
        dlg = AdvancedOptionsDialog(current_func, base_config, gatherer_prompt, annotator_prompt)
        if dlg.exec_():
            results = dlg.get_results()

            # Use custom config for this analysis only
            config = base_config
            config["OPENAI_MODEL"] = results["OPENAI_MODEL"]
            gatherer_context = results["gatherer_context"].strip()
            annotator_context = results["annotator_context"].strip()
            config["rename_filter_enabled"] = results["RENAME_FILTER_ENABLED"]
            config["fast_mode"] = results["fast_mode"]
            config["custom_user_prompt"] = annotator_context
            manual_mode = results["manual_mode"]
            manual_functions = results["manual_functions"]
            extra_option = ["USE_DESC", "USE_COMMENTS", "RENAME_VARS", "RENAME_FUNCS"]
            config.update({k: results[k] for k in extra_option if k in results})

            if manual_mode and not manual_functions:
                ida_kernwin.warning("Manual mode selected but no functions were chosen. Please select functions or use automatic mode.")
                return 1

            # Save custom prompts to netnode
            save_custom_prompts(gatherer_context, annotator_context)

            def aether_thread():
                try:
                    # Validate configuration first
                    validation_success, validation_msg = run_async_in_ida(validate_analysis_config(config))
                    if not validation_success:
                        ida_kernwin.warning(f"Configuration validation failed:\n\n{validation_msg}")
                        return

                    # Choose gatherer based on mode
                    if manual_mode:
                        print("[AETHER] Running manual gatherer...")
                        config["manual_functions"] = manual_functions
                        gatherer_success, starting_function, gatherer_output = run_async_in_ida(run_manual_gatherer_agent(config))
                    else:
                        print("[AETHER] Running automatic gatherer...")
                        # Run gatherer with custom context
                        # Errrrr enjoy ig.
                        if gatherer_context:
                            orig_call = call_openai_llm_gatherer
                            def call_with_context(prompt_content, *args, **kwargs):
                                prompt_content += f"\n\n---\nUSER-PROVIDED ADDITIONAL CONTEXT FOR GATHERER:\n{gatherer_context}\n---\n"
                                return orig_call(prompt_content, *args, **kwargs)
                            import ainalyse.gatherer
                            ainalyse.gatherer.call_openai_llm_gatherer = call_with_context
                            try:
                                gatherer_success, starting_function, gatherer_output = run_async_in_ida(run_gatherer_agent(config))
                            finally:
                                ainalyse.gatherer.call_openai_llm_gatherer = orig_call
                        else:
                            gatherer_success, starting_function, gatherer_output = run_async_in_ida(run_gatherer_agent(config))

                    annotator_output = ""
                    if gatherer_success:
                        print("[AETHER] Gatherer completed successfully. Waiting 3 seconds before starting annotator...")
                        time.sleep(3)
                        annotator_result, annotator_llm_output = run_async_in_ida(run_annotator_agent(config))
                        if annotator_result:
                            annotator_output = annotator_llm_output
                            add_analysis_entry(gatherer_output or "", annotator_output, starting_function or current_func, gatherer_context, annotator_context)
                    else:
                        print("[AETHER] Gatherer failed or did not complete. Skipping annotator.")
                except Exception as e:
                    print(f"[AETHER] Error running AETHER (advanced): {e}")
                    traceback.print_exc()
                print("[AETHER] Done (advanced options).")

            run_in_background(aether_thread)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

class ManualAnalyseHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        config = load_config()

        # Use common validation function
        if not check_config_and_show_error_if_invalid(config):
            return 1

        # Get current function
        current_func = get_current_function_name()
        try:
            ea = ida_kernwin.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func:
                ida_kernwin.warning("No function found at current location.")
                return 1

            current_func_addr = hex(func.start_ea)
        except Exception:
            ida_kernwin.warning("Unable to get current function address.")
            return 1
        # Show manual gatherer dialog using shared FunctionSelectionDialog
        dlg = FunctionSelectionDialog(current_func, current_func_addr, "Manual Gatherer - Select Functions")
        if dlg.exec_():
            selected_functions = dlg.get_selected_functions()
            if not selected_functions:
                print("[AETHER] No functions selected for manual gathering.")
                return 1

            print(f"[AETHER] Starting manual analysis with {len(selected_functions)} selected functions...")
            config["manual_functions"] = selected_functions
            config["custom_user_prompt"] = ""
            config["fast_mode"] = True  # Enable fast mode by default for manual analysis

            def manual_aether_thread():
                try:
                    # Validate configuration first
                    validation_success, validation_msg = run_async_in_ida(validate_analysis_config(config))
                    if not validation_success:
                        ida_kernwin.warning(f"Configuration validation failed:\n\n{validation_msg}")
                        return

                    # Run manual gatherer
                    gatherer_success, starting_function, gatherer_output = run_async_in_ida(run_manual_gatherer_agent(config))
                    annotator_output = ""
                    if gatherer_success:
                        print("[AETHER] Manual gatherer completed successfully. Waiting 3 seconds before starting annotator...")
                        time.sleep(3)
                        annotator_result, annotator_llm_output = run_async_in_ida(run_annotator_agent(config))
                        if annotator_result:
                            annotator_output = annotator_llm_output
                            add_analysis_entry(gatherer_output or "", annotator_output, starting_function or current_func)
                    else:
                        print("[AETHER] Manual gatherer failed or did not complete. Skipping annotator.")
                except Exception as e:
                    print(f"[AETHER] Error running manual AETHER: {e}")
                    traceback.print_exc()
                print("[AETHER] Manual analysis done.")

            run_in_background(manual_aether_thread)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

class PluginSettingsHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        config = load_config()
        from ainalyse.dialogs_ida import PluginSettingsDialog
        dlg = PluginSettingsDialog(config)
        if dlg.exec_():
            new_config = dlg.get_config()
            if save_config(new_config):
                print("[AETHER] Plugin settings saved successfully.")
            else:
                ida_kernwin.warning("Failed to save plugin settings.")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class RetryAnnotationHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):  # noqa: C901
        # Read history on main thread first
        history = read_analysis_history()
        if not history:
            print("[AETHER] No analysis history found for retry.")
            return 1

        latest_entry = history[-1]
        config = load_config()  # Load config here

        # GET ALL IDA INFORMATION ON MAIN THREAD BEFORE STARTING BACKGROUND THREAD
        try:
            starting_function_name = latest_entry.get("starting_function", "unknown")

            # Find the function by name to get its address
            starting_func_addr = None

            for func_ea in idautils.Functions():
                func_name = ida_funcs.get_func_name(func_ea)
                if func_name == starting_function_name:
                    starting_func_addr = hex(func_ea)
                    break

            if not starting_func_addr:
                print(f"[AETHER] [Retry] Could not find function '{starting_function_name}' for retry.")
                return 1

        except Exception as e:
            print(f"[AETHER] [Retry] Unable to get function information: {e}")
            return 1

        def retry_thread():
            try:
                print("[AETHER] [Retry] Undoing latest analysis annotations...")
                undo_success = run_async_in_ida(undo_analysis_annotations(latest_entry, config))

                if undo_success:
                    print("[AETHER] [Retry] Undo completed. Starting fresh analysis with manual gatherer using default selection...")
                    time.sleep(1)  # Brief pause after undo

                    # Collect functions using default selection criteria (same as quick analysis)
                    selected_functions_container = {"functions": []}

                    def _collect_functions_sync():
                        try:
                            result = collect_functions_with_default_criteria(
                                starting_func_addr, starting_function_name, 
                                depth=0, max_depth=5
                            )
                            selected_functions_container["functions"] = result
                            return len(result)  # Return count for execute_sync
                        except Exception as e:
                            print(f"[AETHER] [Retry] Error in function collection: {e}")
                            selected_functions_container["functions"] = []
                            return 0

                    # Execute the collection and get the result from container
                    ida_kernwin.execute_sync(_collect_functions_sync, ida_kernwin.MFF_READ)
                    selected_functions = selected_functions_container["functions"]

                    print(f"[AETHER] [Retry] Auto-selected {len(selected_functions)} functions using default criteria")

                    # Set up config for manual gatherer with auto-selected functions
                    gatherer_context = latest_entry.get("gatherer_prompt", "")
                    annotator_context = latest_entry.get("annotator_prompt", "")
                    config["custom_user_prompt"] = annotator_context
                    config["manual_functions"] = selected_functions
                    config["fast_mode"] = True  # Enable fast mode for retry

                    # Use manual gatherer with auto-selected functions
                    print("[AETHER] [Retry] Starting manual gatherer with auto-selected functions...")
                    gatherer_success, starting_function, gatherer_output = run_async_in_ida(run_manual_gatherer_agent(config))

                    if gatherer_success:
                        print("[AETHER] [Retry] Manual gatherer completed successfully. Waiting 3 seconds before starting annotator...")
                        time.sleep(3)
                        annotator_result, annotator_llm_output = run_async_in_ida(run_annotator_agent(config))
                        if annotator_result:
                            # Use execute_sync to safely update history from main thread
                            def update_history():
                                history = read_analysis_history()
                                if history:
                                    history.pop()  # Remove latest entry
                                    write_analysis_history(history)
                                add_analysis_entry(gatherer_output or "", annotator_llm_output, starting_function or starting_function_name, gatherer_context, annotator_context)
                                return True

                            ida_kernwin.execute_sync(update_history, ida_kernwin.MFF_WRITE)
                            print("[AETHER] [Retry] Analysis retry completed successfully using manual gatherer.")
                        else:
                            print("[AETHER] [Retry] Annotator failed during retry.")
                    else:
                        print("[AETHER] [Retry] Manual gatherer failed during retry.")
                else:
                    print("[AETHER] [Retry] Undo operation failed. Retry aborted.")

            except Exception as e:
                print(f"[AETHER] [Retry] Error during retry: {e}")
                traceback.print_exc()

        run_in_background(retry_thread)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class UndoAnnotationHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Read history on main thread first
        history = read_analysis_history()
        if not history:
            print("[AETHER] No analysis history found for undo.")
            return 1
        latest_entry = history[-1]

        # Load configuration before using it in the thread
        config = load_config()

        def undo_thread():
            try:
                print("[AETHER] [Undo] Starting undo of latest analysis...")
                undo_success = run_async_in_ida(undo_analysis_annotations(latest_entry, config))

                if undo_success:
                    # Use execute_sync to safely access netnode from main thread
                    def remove_from_history():
                        history = read_analysis_history()
                        if history:
                            history.pop()
                            write_analysis_history(history)
                            print("[AETHER] [Undo] Analysis entry removed from history.")
                        return True

                    ida_kernwin.execute_sync(remove_from_history, ida_kernwin.MFF_WRITE)
                    print("[AETHER] [Undo] Undo completed successfully. You may need to refresh (F5) to see changes.")
                else:
                    print("[AETHER] [Undo] Undo operation failed or had limited success.")

            except Exception as e:
                print(f"[AETHER] [Undo] Error during undo: {e}")
                traceback.print_exc()

        run_in_background(undo_thread)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class AnalysisHistoryHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        history = read_analysis_history()
        if not history:
            print("[AETHER] (No analysis history stored yet)")
            return 1
        from ainalyse.dialogs_ida import AnalysisHistoryDialog
        dlg = AnalysisHistoryDialog(history)
        dlg.exec_()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

class WhatsNewHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        changelog_path = os.path.join(os.path.dirname(__file__), "ainalyse", "changelog.txt")

        try:
            with open(changelog_path, "r", encoding="utf-8") as f:
                changelog_content = f.read()
        except FileNotFoundError:
            changelog_content = "Changelog file not found at: " + changelog_path
        except Exception as e:
            changelog_content = f"Error reading changelog: {e}"

        # Create a simple dialog to display the changelog
        class WhatsNewDialog(QtWidgets.QDialog):
            def __init__(self, content, parent=None):
                super(WhatsNewDialog, self).__init__()
                self.setWindowTitle("Changelog")
                self.setMinimumSize(700, 500)

                layout = QtWidgets.QVBoxLayout()

                # Header
                ver_file = open(os.path.join(os.path.dirname(__file__), "ainalyse/version.txt"), "r")
                header_label = QtWidgets.QLabel(f"What's New in AETHER Release {ver_file.read()}")
                ver_file.close()
                header_label.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 10px;")
                layout.addWidget(header_label)

                # Changelog content
                changelog_text = QtWidgets.QTextEdit()
                changelog_text.setPlainText(content)
                changelog_text.setReadOnly(True)
                layout.addWidget(changelog_text)

                # Close button
                button_layout = QtWidgets.QHBoxLayout()
                button_layout.addStretch()

                close_button = QtWidgets.QPushButton("Close")
                close_button.clicked.connect(self.accept)
                button_layout.addWidget(close_button)

                layout.addLayout(button_layout)
                self.setLayout(layout)

        dlg = WhatsNewDialog(changelog_content)
        dlg.exec_()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# --- UI Hooks for Submenu ---
class AETHERUIHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE:
            return

        menu_path = "AETHER AI-RE/"
        ai_decomp_submenu_path = "AETHER AI-RE/AI Rewrite Decompilation/"
        undo_retry_submenu_path = "AETHER AI-RE/Undo or Retry.../"        

        ver_file = open(os.path.join(os.path.dirname(__file__), "ainalyse/version.txt"), "r")

        actions = [
            ("aether:whats_new", f"What's new in release {ver_file.read()} (changelog)", WhatsNewHandler(), "", ""),
            ("aether:fast_look", "Annotate only this function", FastLookHandler(), "Ctrl+Alt+F", ""),
            ("aether:quick", "Annotate function tree with default selection", QuickAnalyseHandler(), "Ctrl+Alt+Q", ""),
            ("aether:struct_creator", "Create struct for highlighted variable", StructRefactorHandler(), "Ctrl+Alt+V", ""),
            ("aether:chatbot", "Open AI Chatbot", ChatbotHandler(), "", ""),
            ("aether:manual", "Manually select functions to analyse", ManualAnalyseHandler(), "", ""),
            ("aether:advanced", "Analyse (advanced options)", AdvancedAnalyseHandler(), "", ""),
            ("aether:history", "AI analysis history", AnalysisHistoryHandler(), "", ""),
            ("aether:settings", "Plugin settings", PluginSettingsHandler(), "", ""),
        ]

        ver_file.close()

        # AI Decompilation submenu actions
        ai_decomp_actions = [
        #     ("ainalyse:ai_decomp", "AI rewrite decompilation (prompt A)", AIDecompHandler(), "", ""),
        #     ("ainalyse:ai_decomp_b", "AI rewrite decompilation (prompt B)", AIDecompHandlerB(), "", ""),
        #     ("ainalyse:ai_decomp_selector", "Select functions for AI rewrite...", AIDecompSelectorHandler(), "", ""),
        #     ("ainalyse:ai_decomp_clear", "Clear all AI rewrites", ClearAIDecompHandler(), "", "")
        ]

        # Undo / Retry submenu actions
        undo_retry_actions = [
            ("aether:retry", "Retry last annotation from here with defaults", RetryAnnotationHandler(), "", ""),
            ("aether:undo", "Undo latest annotation", UndoAnnotationHandler(), "", ""),
            ("aether:custom_reannotate", "Re-annotate this function with custom prompt", CustomPromptReAnnotateHandler(), "", ""),
            ("aether:strip_annotations", "Strip AI's annotations for this function", StripAIAnnotationsHandler(), "", ""),
        ]

        # Register main actions
        for action_name, label, handler, hotkey, tooltip in actions:
            if not ida_kernwin.get_action_state(action_name)[0]:  # Check if action exists
                action_desc = ida_kernwin.action_desc_t(
                    action_name, label, handler, hotkey, tooltip, -1
                )
                ida_kernwin.register_action(action_desc)
            ida_kernwin.attach_action_to_popup(widget, popup, action_name, menu_path)

        # Register AI decompilation actions and add to submenu
        for action_name, label, handler, hotkey, tooltip in ai_decomp_actions:
            if not ida_kernwin.get_action_state(action_name)[0]:  # Check if action exists
                action_desc = ida_kernwin.action_desc_t(
                    action_name, label, handler, hotkey, tooltip, -1
                )
                ida_kernwin.register_action(action_desc)
            ida_kernwin.attach_action_to_popup(widget, popup, action_name, ai_decomp_submenu_path)

        # Register undo/retry actions and add to submenu
        for action_name, label, handler, hotkey, tooltip in undo_retry_actions:
            if not ida_kernwin.get_action_state(action_name)[0]:  # Check if action exists
                action_desc = ida_kernwin.action_desc_t(
                    action_name, label, handler, hotkey, tooltip, -1
                )
                ida_kernwin.register_action(action_desc)
            ida_kernwin.attach_action_to_popup(widget, popup, action_name, undo_retry_submenu_path)

class AETHERPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
    comment = "AETHER AI-RE: AI Engine To Help The Engineer Reverse"
    help = "Right-click in Pseudocode view and select 'AETHER'"
    wanted_name = "AETHER"
    wanted_hotkey = ""

    def __init__(self):
        self.ui_hooks = None
        icon_path = os.path.join(os.path.dirname(__file__), "ainalyse/brain.png")

        # Load custom icon
        icon_data = idaapi.load_custom_icon(icon_path)
        if not icon_data:
            print(f"Failed to load icon from {icon_path}")
            # Use a default icon if loading fails
            icon_data = idaapi.load_custom_icon("ainalyse/brain.png")

        action_desc2 = idaapi.action_desc_t(
            "aether:fast_look2",
            'AETHER AI-RE: Focus and annotate just this function (takes ~25s)',
            FastLookHandler(),
            '',
            'AETHER AI-RE: Focus and annotate just this function (takes ~25s). Much faster than a full analysis.',
            icon_data,
        )

        # Register the action
        if not idaapi.register_action(action_desc2):
            print("Failed to register action.")

        # Attach the action to the toolbar
        idaapi.attach_action_to_toolbar("AnalysisToolBar", "aether:fast_look2")

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            print("[AETHER] Hex-Rays is not available.")
            return ida_idaapi.PLUGIN_SKIP

        # Create default config if it doesn't exist
        create_default_config()

        # Load config and auto-populate missing models
        config = load_config()
        print(f"[AETHER] Plugin initialized with models: OPENAI_MODEL='{config.get('OPENAI_MODEL', '')}', GATHERER_MODEL='{config.get('GATHERER_MODEL', '')}', ANNOTATOR_MODEL='{config.get('ANNOTATOR_MODEL', '')}', AI_DECOMP_MODEL='{config.get('AI_DECOMP_MODEL', '')}', SINGLE_ANALYSIS_MODEL='{config.get('SINGLE_ANALYSIS_MODEL', '')}'")

        if not ASYNC_WORKER.is_alive():
            print("[AETHER] [Async Manager] Initializing asyncio background thread...")
            ASYNC_WORKER.start()

        self.ui_hooks = AETHERUIHooks()
        self.ui_hooks.hook()

        # Install AI decompilation hooks
        install_ai_decomp_hooks()

        # Start MCP Plugin
        def start_mcp():
            ida_loader.load_and_run_plugin("mcp-plugin", 0)
            if is_mcp_running():
                return -1
            return 1000

        def is_mcp_running(port=13337):
            """Checks if the MCP port (13337 by default in mcp-plugin.py) is already occupied."""
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("127.0.0.1", port))
                    return False
                except OSError:
                    return True

        ida_kernwin.register_timer(1000, start_mcp)

        print("[AETHER] Plugin initialized. Right-click in Pseudocode view.")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        print("[AETHER] Use the context menu in Pseudocode view.")

    def term(self):
        if self.ui_hooks:
            self.ui_hooks.unhook()

        # Remove AI decompilation hooks
        remove_ai_decomp_hooks()

        # Unregister all actions
        actions = [
            "aether:whats_new",
            "aether:fast_look",
            "aether:quick",
            "aether:struct_creator",
            "aether:advanced",
            "aether:manual",
            "aether:ai_decomp",
            "aether:ai_decomp_b",
            "aether:retry",
            "aether:undo",
            "aether:history",
            "aether:settings",
            "aether:ai_decomp_selector",
            "aether:ai_decomp_clear",
            "aether:custom_reannotate",
            "aether:strip_annotations"
        ]
        for action_name in actions:
            ida_kernwin.unregister_action(action_name)

        # Close AI decompilation viewer if open
        widget = ida_kernwin.find_widget(AI_DECOMP_VIEW_TITLE)
        if widget:
            ida_kernwin.close_widget(widget, 0)

        print("[AETHER] Plugin terminated.")

def PLUGIN_ENTRY():
    return AETHERPlugin()

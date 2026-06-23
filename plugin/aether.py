import os
import time
import traceback
import socket

# for the auto-update
import json
import base64
import shutil
import tempfile
import zipfile
import urllib.error
import urllib.request

from copy import deepcopy

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
from ainalyse.async_manager import ensure_async_pool, get_primary_worker, run_async_in_ida, run_in_background, shutdown_async_runtime
from ainalyse.chatbot import CHATBOT_VIEW_TITLE as CHATBOT_VIEW_TITLE, show_chatbot_viewer as show_chatbot_v2_viewer
from ainalyse.chatbot.chatbot_pygen.python_script_generation import DeobfuscateHandler, cleanup_pygen as cleanup_python_gen

# --- Dialog imports ---
from ainalyse.dialogs_ida import AdvancedOptionsDialog, AnalysisHistoryDialog, PluginSettingsDialog
from ainalyse.function_selection import (
    FunctionSelectionDialog,  # Use shared dialog instead of ManualGathererDialog
    collect_functions_with_default_criteria,
)
from ainalyse.gatherer import call_openai_llm_gatherer, run_gatherer_agent

# --- AETHER specific imports ---
from ainalyse.manual_gatherer import run_manual_gatherer_agent
from ainalyse.quick_analyse import QuickAnalyseHandler
from ainalyse.realtime.handlers import CustomPromptReAnnotateHandler, FastLookHandler, SmartLookHandler, StripAIAnnotationsHandler, GenerateReportHandler
from ainalyse.unflattener.handlers import UnflattenerHandler
from ainalyse.unflattener.viewer import AI_DEOBFS_VIEW_TITLE
from ainalyse.undo_retry import undo_analysis_annotations
from ainalyse.struct_creator.handler import StructCreationHandler as StructRefactorHandler
from ainalyse.utils import refresh_functions

from ainalyse.indexing import FunctionIndexer, FunctionIndexManager, ImportanceLevel, get_program_identifier, get_index_filepath
from ainalyse.fullanalysis.orchestrator import AetherOrchestrator

from ainalyse.qt_shim import QtCore, QtWidgets

# --- Output File Paths ---
CTX_FILE_PATH = os.path.join(os.path.dirname(__file__), "ainalyse", "ctx.txt")
VERBOSE_LOG_PATH = os.path.join(os.path.dirname(__file__), "ainalyse", "verbose.txt")

# --- Module Level Guards ---
_GLOBAL_TERMINATED = False

# --- Action Handlers ---

_global_orchestrator = None

class AutoAnalyseBinaryHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global _global_orchestrator
        
        if _global_orchestrator is not None and _global_orchestrator.is_running:
            _global_orchestrator.stop()
            ida_kernwin.update_action_label("aether:auto_analyse", "Auto-Analyze Binary")
            return 1

        config = load_config()
        if not check_config_and_show_error_if_invalid(config):
            return 0
        
        _global_orchestrator = AetherOrchestrator(config=config)
        
        # Change label using standard update API call
        ida_kernwin.update_action_label("aether:auto_analyse", "STOP Auto-Analyze")
        
        _global_orchestrator.run_analysis()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChatbotHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        show_chatbot_v2_viewer()
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

        dlg = AdvancedOptionsDialog(current_func, base_config, gatherer_prompt, annotator_prompt)
        if dlg.exec_():
            results = dlg.get_results()

            # Use custom config for this analysis only
            config = deepcopy(base_config)
            config["OPENAI_MODEL"] = results["OPENAI_MODEL"]
            gatherer_context = results["gatherer_context"].strip()
            annotator_context = results["annotator_context"].strip()
            rename_filter_enabled = results.get("RENAME_FILTER_ENABLED", results.get("rename_filter_enabled", True))
            # Keep both keys for backward compatibility across existing call sites.
            config["RENAME_FILTER_ENABLED"] = rename_filter_enabled
            config["rename_filter_enabled"] = rename_filter_enabled
            config["fast_mode"] = results["fast_mode"]
            config["custom_user_prompt"] = annotator_context
            manual_mode = results["manual_mode"]
            manual_functions = results["manual_functions"]
            extra_option = ["USE_DESC", "USE_COMMENTS", "USE_RENAME_VARS", "USE_RENAME_FUNCS"]
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
                    refresh_functions(fallback_func_addr=starting_func_addr, log_prefix="[AETHER] [Retry]")
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
                            refresh_functions(selected_functions, starting_func_addr, log_prefix="[AETHER] [Retry]")
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
                with open(os.path.join(os.path.dirname(__file__), "ainalyse/version.txt"), "r") as ver_file:
                    header_label = QtWidgets.QLabel(f"What's New in AETHER Release {ver_file.read()}")
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

# --- Indexing Action Handlers ---

class IndexBinaryHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        config = load_config()
        if not check_config_and_show_error_if_invalid(config):
            return 1

        if FunctionIndexManager.is_binary_indexed():
            choice = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_NO,
                "Binary is already indexed. Re-index?"
            )
            if choice != ida_kernwin.ASKBTN_YES:
                return 1

        if FunctionIndexer.is_indexing_in_progress():
            ida_kernwin.warning("Indexing is already in progress.")
            return 1

        def on_success(index):
            ida_kernwin.execute_sync(
                lambda: ida_kernwin.info(
                    f"Indexing complete: {index.size()} functions classified"
                ),
                ida_kernwin.MFF_FAST,
            )

        def on_failure(msg):
            ida_kernwin.execute_sync(
                lambda: ida_kernwin.info(msg) if "paused" in msg.lower() else ida_kernwin.warning(f"Indexing failed: {msg}"),
                ida_kernwin.MFF_FAST,
            )

        if FunctionIndexManager.can_resume_indexing():
            run_in_background(lambda: FunctionIndexer.resume_indexing(on_success, on_failure))
        else:
            run_in_background(lambda: FunctionIndexer.index_binary(on_success, on_failure))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class CancelIndexingHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if FunctionIndexer.is_indexing_in_progress():
            cancelled = FunctionIndexer.request_cancellation()
            if cancelled:
                print("[AETHER] Indexing cancellation requested.")
            else:
                ida_kernwin.warning("Failed to request cancellation.")
        else:
            ida_kernwin.warning("No indexing operation is currently running.")
        return 1

    def update(self, ctx):
        if FunctionIndexer.is_indexing_in_progress():
            return ida_kernwin.AST_ENABLE_ALWAYS
        return ida_kernwin.AST_DISABLE


class ReindexBinaryHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        config = load_config()
        if not check_config_and_show_error_if_invalid(config):
            return 1

        if FunctionIndexer.is_indexing_in_progress():
            ida_kernwin.warning("Indexing is already in progress.")
            return 1

        choice = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            "This will delete the existing index and re-index the entire binary. Continue?"
        )
        if choice != ida_kernwin.ASKBTN_YES:
            return 1

        # Clear existing index first
        FunctionIndexManager.clear_index_completely()

        def on_success(index):
            ida_kernwin.execute_sync(
                lambda: ida_kernwin.info(
                    f"Re-indexing complete: {index.size()} functions classified"
                ),
                ida_kernwin.MFF_FAST,
            )

        def on_failure(msg):
            ida_kernwin.execute_sync(
                lambda: ida_kernwin.warning(f"Re-indexing failed: {msg}"),
                ida_kernwin.MFF_FAST,
            )

        run_in_background(lambda: FunctionIndexer.index_binary(on_success, on_failure))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class IndexStatsHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        idx = FunctionIndexManager.get_index()

        if idx.is_empty():
            ida_kernwin.info("No index exists for this binary yet.\nUse 'Index Binary' to create one.")
            return 1

        # Collect importance counts
        importance_counts = {}
        for entry in idx.entries_by_address.values():
            level = entry.get_importance_level() or "UNKNOWN"
            importance_counts[level] = importance_counts.get(level, 0) + 1

        # Collect category counts
        category_counts = {}
        for entry in idx.entries_by_address.values():
            for cat in entry.get_functional_categories():
                category_counts[cat] = category_counts.get(cat, 0) + 1

        # Build stats text
        lines = []
        lines.append(f"Program: {idx.program_name or 'unknown'}")
        lines.append(f"State: {idx.indexing_state}")
        lines.append(f"Total indexed: {idx.size()} / {idx.total_function_count} functions")
        lines.append(f"Tokens used: {idx.total_tokens_used:,}")
        lines.append("")

        bm = idx.batch_metadata
        lines.append(f"Batches: {bm.completed_batches} / {bm.total_batches}")
        lines.append("")

        lines.append("--- Importance ---")
        for level_name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"):
            count = importance_counts.get(level_name, 0)
            if count:
                lines.append(f"  {level_name}: {count}")
        unknown_imp = importance_counts.get("UNKNOWN", 0)
        if unknown_imp:
            lines.append(f"  UNKNOWN: {unknown_imp}")
        lines.append("")

        lines.append("--- Categories (top 15) ---")
        sorted_cats = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:15]
        for cat, cnt in sorted_cats:
            lines.append(f"  {cat}: {cnt}")

        # Decompile blacklist summary
        lines.append("")
        lines.append("--- Decompile Skips (heavy) ---")
        blacklist_items = list(getattr(idx, "decompile_blacklist", {}).items())
        lines.append(f"  Total skipped: {len(blacklist_items)}")
        for addr, meta in blacklist_items[:10]:
            name = (meta or {}).get("name", "")
            lines.append(f"  {addr} {name}")
        if len(blacklist_items) > 10:
            lines.append(f"  ... ({len(blacklist_items) - 10} more)")

        # LLM parse failure summary
        lines.append("")
        lines.append("--- LLM Missing Entries ---")
        failed_items = list(getattr(idx, "llm_failed_entries", {}).items())
        lines.append(f"  Total missing: {len(failed_items)}")
        for addr, meta in failed_items[:10]:
            name = (meta or {}).get("name", "")
            lines.append(f"  {addr} {name}")
        if len(failed_items) > 10:
            lines.append(f"  ... ({len(failed_items) - 10} more)")

        # Footnote with file location
        lines.append("")
        lines.append("─" * 40)
        try:
            identifier = get_program_identifier()
            index_path = get_index_filepath(identifier)
            lines.append(f"Index file: {index_path}")
        except Exception:
            lines.append("Index file: (could not determine path)")

        stats_text = "\n".join(lines)

        class IndexStatsDialog(QtWidgets.QDialog):
            def __init__(self, text, parent=None):
                super().__init__(parent)
                self.setWindowTitle("Function Index Statistics")
                self.setMinimumSize(500, 450)

                layout = QtWidgets.QVBoxLayout()

                header = QtWidgets.QLabel("Function Index Statistics")
                header.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 10px;")
                layout.addWidget(header)

                text_area = QtWidgets.QTextEdit()
                text_area.setPlainText(text)
                text_area.setReadOnly(True)
                text_area.setStyleSheet("font-family: Consolas, monospace;")
                layout.addWidget(text_area)

                btn_layout = QtWidgets.QHBoxLayout()
                btn_layout.addStretch()
                close_btn = QtWidgets.QPushButton("Close")
                close_btn.clicked.connect(self.accept)
                btn_layout.addWidget(close_btn)
                layout.addLayout(btn_layout)

                self.setLayout(layout)

        dlg = IndexStatsDialog(stats_text)
        dlg.exec_()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


# --- UI Hooks for Submenu ---
class AetherUIHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE:
            return

        menu_path = "AETHER AI-RE/"
        experimental_submenu_path = "AETHER AI-RE/Experimental/"
        ai_decomp_submenu_path = "AETHER AI-RE/AI Rewrite Decompilation/"
        undo_retry_submenu_path = "AETHER AI-RE/Undo or Retry.../"
        indexing_submenu_path = "AETHER AI-RE/Indexing/"

        with open(os.path.join(os.path.dirname(__file__), "ainalyse/version.txt"), "r") as ver_file:

            actions = [
                ("aether:whats_new", f"What's new in release {ver_file.read()} (changelog)", WhatsNewHandler(), "", ""),
                ("aether:fast_look", "Annotate only this function", FastLookHandler(), "Ctrl+Alt+F", ""),
                ("aether:smart_look", "Annotate only this function with Smart Select", SmartLookHandler(), "Ctrl+Alt+S", ""),
                ("aether:quick", "Annotate function tree with default selection", QuickAnalyseHandler(), "Ctrl+Alt+Q", ""),
                ("aether:struct_creator", "Create struct for highlighted variable", StructRefactorHandler(), "Ctrl+Alt+V", ""),
                ("aether:chatbot", "Open AI Chatbot", ChatbotHandler(), "", ""),
                ("aether:manual", "Manually select functions to analyse", ManualAnalyseHandler(), "", ""),
                ("aether:advanced", "Analyse (advanced options)", AdvancedAnalyseHandler(), "", ""),
                ("aether:history", "AI analysis history", AnalysisHistoryHandler(), "", ""),
                ("aether:settings", "Plugin settings", PluginSettingsHandler(), "", ""),
            ]

        # Experimental submenu actions
        experimental_actions = [
            ("aether:generate_report", "Generate Report on this function", GenerateReportHandler(), "Ctrl+Alt+G", ""),
            ("aether:unflatten", "AI Unflatten", UnflattenerHandler(), "", ""),
            ("aether:auto_analyse", "Auto-Analyze Binary", AutoAnalyseBinaryHandler(), "", ""),                
        ]

        # AI Decompilation submenu actions
        ai_decomp_actions = [
        #     ("aether:ai_decomp", "AI rewrite decompilation (prompt A)", AIDecompHandler(), "", ""),
        #     ("aether:ai_decomp_b", "AI rewrite decompilation (prompt B)", AIDecompHandlerB(), "", ""),
        #     ("aether:ai_decomp_selector", "Select functions for AI rewrite...", AIDecompSelectorHandler(), "", ""),
        #     ("aether:ai_decomp_clear", "Clear all AI rewrites", ClearAIDecompHandler(), "", "")
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

        # Register experimental actions and add to submenu
        for action_name, label, handler, hotkey, tooltip in experimental_actions:
            if not ida_kernwin.get_action_state(action_name)[0]:  # Check if action exists
                action_desc = ida_kernwin.action_desc_t(
                    action_name, label, handler, hotkey, tooltip, -1
                )
                ida_kernwin.register_action(action_desc)
            ida_kernwin.attach_action_to_popup(widget, popup, action_name, experimental_submenu_path)

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

        # Indexing submenu actions
        indexing_actions = [
            ("aether:index_binary", "Index / Resume Binary", IndexBinaryHandler(), "", ""),
            ("aether:cancel_indexing", "Cancel Indexing", CancelIndexingHandler(), "", ""),
            ("aether:reindex_binary", "Re-index Binary", ReindexBinaryHandler(), "", ""),
            ("aether:index_stats", "Index Statistics", IndexStatsHandler(), "", ""),
        ]

        # Register indexing actions and add to submenu
        for action_name, label, handler, hotkey, tooltip in indexing_actions:
            if not ida_kernwin.get_action_state(action_name)[0]:
                action_desc = ida_kernwin.action_desc_t(
                    action_name, label, handler, hotkey, tooltip, -1
                )
                ida_kernwin.register_action(action_desc)
            ida_kernwin.attach_action_to_popup(widget, popup, action_name, indexing_submenu_path)

class AETHERPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
    comment = "AETHER AI-RE: AI Engine To Help The Engineer Reverse"
    help = "Right-click in Pseudocode view and select 'AETHER'"
    wanted_name = "AETHER"
    wanted_hotkey = ""

    def __init__(self):
        self.ui_hooks = None
        self._toolbar_action_name = "aether:fast_look2"
        self._toolbar_icon_id = None
        self._mcp_timer = None
        self._terminated = False

    
    _GITHUB_OWNER = "CSIT-SG"
    _GITHUB_REPO = "AETHER"
    _GITHUB_BRANCH = "main"
    _VERSION_FILE_PATH = "plugin/ainalyse/version.txt"

    def _get_local_version(self):
        version_path = os.path.join(os.path.dirname(__file__), "ainalyse", "version.txt")
        try:
            with open(version_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return ""

    def _split_version(self, version_str):
        parts = []
        for chunk in str(version_str or "").strip().split("."):
            try:
                parts.append(int(chunk))
            except ValueError:
                parts.append(0)
        return parts

    def _is_remote_version_newer(self, local_version, remote_version):
        local_parts = self._split_version(local_version)
        remote_parts = self._split_version(remote_version)
        max_len = max(len(local_parts), len(remote_parts))
        local_parts.extend([0] * (max_len - len(local_parts)))
        remote_parts.extend([0] * (max_len - len(remote_parts)))
        return tuple(remote_parts) > tuple(local_parts)

    def _github_request(self, url, token=None):
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "AETHER-IDA-Updater",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.read()

    def _fetch_remote_version(self, token=None):
        version_url = f"https://raw.githubusercontent.com/{self._GITHUB_OWNER}/{self._GITHUB_REPO}/{self._GITHUB_BRANCH}/{self._VERSION_FILE_PATH}"
        payload = self._github_request(version_url, token).decode("utf-8").strip()
        if not payload:
            return ""
        return payload

    def _download_and_install_update(self, token=None):
        zip_url = f"https://api.github.com/repos/{self._GITHUB_OWNER}/{self._GITHUB_REPO}/zipball/{self._GITHUB_BRANCH}"
        plugins_dir = os.path.dirname(__file__)

        with tempfile.TemporaryDirectory(prefix="aether_update_") as temp_dir:
            archive_path = os.path.join(temp_dir, "repo.zip")
            with open(archive_path, "wb") as f:
                f.write(self._github_request(zip_url, token))

            extract_dir = os.path.join(temp_dir, "extract")
            os.makedirs(extract_dir, exist_ok=True)

            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                zip_ref.extractall(extract_dir)

            roots = [
                os.path.join(extract_dir, item)
                for item in os.listdir(extract_dir)
                if os.path.isdir(os.path.join(extract_dir, item))
            ]
            if not roots:
                raise RuntimeError("Downloaded archive does not contain expected repository root")

            repo_root = roots[0]
            source_plugin_py = os.path.join(repo_root, "plugin", "aether.py")
            source_ainalyse_dir = os.path.join(repo_root, "plugin", "ainalyse")

            if not os.path.isfile(source_plugin_py):
                raise RuntimeError("plugin/aether.py not found in downloaded update")
            if not os.path.isdir(source_ainalyse_dir):
                raise RuntimeError("plugin/ainalyse not found in downloaded update")

            target_plugin_py = os.path.join(plugins_dir, "aether.py")
            target_ainalyse_dir = os.path.join(plugins_dir, "ainalyse")
            backup_plugin_py = target_plugin_py + ".bak"
            backup_ainalyse_dir = target_ainalyse_dir + ".bak"

            if os.path.exists(backup_plugin_py):
                os.remove(backup_plugin_py)
            if os.path.isdir(backup_ainalyse_dir):
                shutil.rmtree(backup_ainalyse_dir)

            plugin_backed_up = False
            ainalyse_backed_up = False
            try:
                if os.path.isfile(target_plugin_py):
                    shutil.copy2(target_plugin_py, backup_plugin_py)
                    plugin_backed_up = True

                if os.path.isdir(target_ainalyse_dir):
                    shutil.move(target_ainalyse_dir, backup_ainalyse_dir)
                    ainalyse_backed_up = True

                shutil.copytree(source_ainalyse_dir, target_ainalyse_dir)
                shutil.copy2(source_plugin_py, target_plugin_py)

                if os.path.isfile(backup_plugin_py):
                    os.remove(backup_plugin_py)
                if os.path.isdir(backup_ainalyse_dir):
                    shutil.rmtree(backup_ainalyse_dir)
            except Exception:
                if os.path.isdir(target_ainalyse_dir):
                    shutil.rmtree(target_ainalyse_dir)
                if ainalyse_backed_up and os.path.isdir(backup_ainalyse_dir):
                    shutil.move(backup_ainalyse_dir, target_ainalyse_dir)

                if plugin_backed_up and os.path.isfile(backup_plugin_py):
                    shutil.copy2(backup_plugin_py, target_plugin_py)

                raise

    def _prompt_yes_no(self, default_button, message):
        answer = {"value": ida_kernwin.ASKBTN_NO}

        def _ask_sync():
            answer["value"] = ida_kernwin.ask_yn(default_button, message)
            return 1

        ida_kernwin.execute_sync(_ask_sync, ida_kernwin.MFF_FAST)
        return answer["value"]

    def _show_info(self, message):
        ida_kernwin.execute_sync(lambda: ida_kernwin.info(message), ida_kernwin.MFF_FAST)

    def _show_warning(self, message):
        ida_kernwin.execute_sync(lambda: ida_kernwin.warning(message), ida_kernwin.MFF_FAST)

    def _check_for_startup_updates(self):
        local_version = self._get_local_version()
        if not local_version:
            return

        config = load_config()
        # token = (
        #     str(config.get("GITHUB_TOKEN", "")).strip()
        #     or str(os.environ.get("AETHER_GITHUB_TOKEN", "")).strip()
        #     or str(os.environ.get("GITHUB_TOKEN", "")).strip()
        # )
        token = None

        try:
            remote_version = self._fetch_remote_version(token)
        except urllib.error.HTTPError as e:
            print(f"[AETHER] [Updater] Version check failed (HTTP {e.code}).")
            return
        except Exception as e:
            print(f"[AETHER] [Updater] Version check failed: {e}")
            return

        if not remote_version:
            return

        if not self._is_remote_version_newer(local_version, remote_version):
            print("[AETHER] [Updater] Current version up to date.")
            return

        choice = self._prompt_yes_no(
            ida_kernwin.ASKBTN_YES,
            (
                "A newer AETHER version is available on 'dev'.\n\n"
                f"Current: {local_version}\n"
                f"Latest:  {remote_version}\n\n"
                "Update now?"
            ),
        )
        if choice != ida_kernwin.ASKBTN_YES:
            return

        try:
            self._download_and_install_update(token)
            self._show_info(
                "AETHER update installed successfully.\n"
                "Please restart IDA to load the new plugin version."
            )
        except Exception as e:
            self._show_warning(f"AETHER update failed: {e}")

    def _register_toolbar_action(self):
        """Register and attach the toolbar action after IDA UI is initialized."""
        icon_path = os.path.join(os.path.dirname(__file__), "ainalyse/brain.png")

        # Load custom icon
        icon_data = idaapi.load_custom_icon(icon_path)
        if not icon_data:
            print(f"Failed to load icon from {icon_path}")
            # Use a default icon if loading fails
            icon_data = idaapi.load_custom_icon("ainalyse/brain.png")
        self._toolbar_icon_id = icon_data

        action_desc2 = idaapi.action_desc_t(
            self._toolbar_action_name,
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
        idaapi.attach_action_to_toolbar("AnalysisToolBar", self._toolbar_action_name)

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            print("[AETHER] Hex-Rays is not available.")
            return ida_idaapi.PLUGIN_SKIP

        try:
            self._register_toolbar_action()
        except Exception as e:
            print(f"[AETHER] Failed to register toolbar action: {e}")

        # Create default config if it doesn't exist
        create_default_config()

        # Load config and auto-populate missing models
        config = load_config()
        print(
            f"[AETHER] Plugin initialized with models: OPENAI_MODEL='{config.get('OPENAI_MODEL', '')}', "
            f"GATHERER_MODEL='{config.get('GATHERER_MODEL', '')}', "
            f"ANNOTATOR_MODEL='{config.get('ANNOTATOR_MODEL', '')}', "
            f"AI_DECOMP_MODEL='{config.get('AI_DECOMP_MODEL', '')}', "
            f"SINGLE_ANALYSIS_MODEL='{config.get('SINGLE_ANALYSIS_MODEL', '')}', "
            f"INDEX_AGENT_MODEL='{config.get('INDEX_AGENT_MODEL', '')}'"
        )

        # Initialize async worker pool after plugin startup to avoid import-time thread side effects.
        ensure_async_pool(allow_reinit=True)
        primary_worker = get_primary_worker()
        if not primary_worker.is_alive():
            print("[AETHER] [Async Manager] Initializing asyncio background thread...")
            primary_worker.start()

        self.ui_hooks = AetherUIHooks()
        self.ui_hooks.hook()

        # Install AI decompilation hooks
        install_ai_decomp_hooks()

        # Start MCP Plugin
        def start_mcp():
            try:
                # Avoid repeated plugin load attempts if MCP is already running.
                if is_mcp_running():
                    self._mcp_timer = None
                    return -1

                ida_loader.load_and_run_plugin("mcp-plugin", 0)
                if is_mcp_running():
                    self._mcp_timer = None
                    return -1

                return 1000
            except Exception as e:
                print(f"[AETHER] [MCP] Failed to auto-start mcp-plugin: {e}")
                # Keep retrying in case startup ordering is transient.
                return 2000

        def is_mcp_running(port=13337):
            """Checks if the MCP port (13337 by default in mcp-plugin.py) is already occupied."""
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("127.0.0.1", port))
                    return False
                except OSError:
                    return True

        self._mcp_timer = ida_kernwin.register_timer(1000, start_mcp)

        # Run update checks asynchronously to avoid blocking plugin initialization.
        run_in_background(self._check_for_startup_updates)

        print("[AETHER] Plugin initialized. Right-click in Pseudocode view.")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        print("[AETHER] Use the context menu in Pseudocode view.")

    def term(self):
        global _GLOBAL_TERMINATED
        if _GLOBAL_TERMINATED:
            return
        _GLOBAL_TERMINATED = True

        print("[AETHER] term(): Starting plugin termination...")

        # Prevent any new async scheduling and stop worker loops before UI teardown.
        shutdown_async_runtime()

        try:
            print("[AETHER] term(): Shutting down global chatbot controller")
            from ainalyse.chatbot.ui.viewer import g_chatbot_controller
            if g_chatbot_controller is not None:
                g_chatbot_controller.shutdown()
        except Exception as e:
            print(f"[AETHER] term(): Error shutting down chatbot controller: {e}")

        # 1. Cleanup other modules
        try:
            print("[AETHER] term(): Cleaning up Python Generation module")
            from ainalyse.chatbot.chatbot_pygen import python_script_generation
            python_script_generation._pygen_shutting_down = True
            cleanup_python_gen()
        except Exception as e:
            print(f"[AETHER] term(): Error cleaning up Python gen: {e}")  

        # 2. Close widgets and unhook
        try:
            aether_widgets = [
                AI_DECOMP_VIEW_TITLE,
                AI_DEOBFS_VIEW_TITLE,
                CHATBOT_VIEW_TITLE,
                "AETHER Chatbot",
                "AETHER IDAPython Generation"
            ]
            for title in aether_widgets:
                    widget = ida_kernwin.find_widget(title)
                    if widget:
                        print(f"[AETHER] term(): Closing widget '{title}'")
                        ida_kernwin.close_widget(widget, 0)
        except Exception as e:
            print(f"[AETHER] term(): Error closing widget '{title}': {e}")

        # Stop timer callbacks on unload
        if self._mcp_timer is not None:
            try:
                timer_to_unregister = self._mcp_timer
                self._mcp_timer = None
                print(f"[AETHER] term(): Unregistering MCP timer {timer_to_unregister}")

                # Check if IDA is still in a valid state for unregistering timers
                if hasattr(ida_kernwin, "unregister_timer"):
                    # In some IDA versions, unregistering during shutdown can be unstable if the timer already fired or is firing.
                    try:
                        if timer_to_unregister:
                            res = ida_kernwin.unregister_timer(timer_to_unregister)
                            if res:
                                print("[AETHER] term(): MCP timer unregistered successfully")
                            else:
                                print("[AETHER] term(): unregister_timer returned False (timer may have already expired)")
                    except Exception as ite:
                        print(f"[AETHER] term(): Note: unregister_timer failed: {ite}")
            except Exception as e:
                print(f"[AETHER] term(): Error during timer cleanup: {e}")

        if self.ui_hooks:
            try:
                # Ensure we are on the main thread and IDA is still alive
                print("[AETHER] term(): Unhooking UI hooks")
                self.ui_hooks.unhook()
                print("[AETHER] term(): UI hooks unhooked")
            except Exception as e:
                # Silently catch unhooking errors if IDA is too far gone
                print(f"[AETHER] term(): Note: Error unhooking UI hooks (IDA may be shutting down): {e}")
            finally:
                self.ui_hooks = None
        try:
            if FunctionIndexer.is_indexing_in_progress():
                print("[AETHER] term(): Cancelling indexing")
                FunctionIndexer.request_cancellation()
        except Exception as e:
            print(f"[AETHER] term(): Error cancelling indexing: {e}")

        # Remove AI decompilation hooks before stopping async workers.
        remove_ai_decomp_hooks()

        try:
            idaapi.detach_action_from_toolbar("AnalysisToolBar", self._toolbar_action_name)
        except Exception as e:
            print(f"[AETHER] term(): Error detaching toolbar: {e}")

        # Unregister all actions
        print("[AETHER] term(): Unregistering actions")
        actions = [
            self._toolbar_action_name,
            "aether:whats_new",
            "aether:fast_look",
            "aether:smart_look",
            "aether:quick",
            "aether:auto_analyse",
            "aether:struct_creator",
            "aether:chatbot",
            "aether:advanced",
            "aether:manual",
            "aether:ai_decomp",
            "aether:ai_decomp_b",
            "aether:generate_report",
            "aether:unflatten",
            "aether:retry",
            "aether:undo",
            "aether:history",
            "aether:settings",
            "aether:ai_decomp_selector",
            "aether:ai_decomp_clear",
            "aether:custom_reannotate",
            "aether:strip_annotations",
            "aether:index_binary",
            "aether:resume_indexing",
            "aether:cancel_indexing",
            "aether:reindex_binary",
            "aether:index_stats",
        ]

        for action_name in actions:
            if not action_name:
                continue
            try:
                # Check if action is still registered before unregistering
                if ida_kernwin.get_action_label(action_name):
                    ida_kernwin.unregister_action(action_name)
            except:
                pass

        if self._toolbar_icon_id and hasattr(idaapi, "free_custom_icon"):
            try:
                print("[AETHER] term(): Freeing toolbar icon")
                idaapi.free_custom_icon(self._toolbar_icon_id)
            except Exception as e:
                print(f"[AETHER] term(): Error freeing icon: {e}")
            self._toolbar_icon_id = None

        if hasattr(self, "ui_hooks") and self.ui_hooks:
            try:
                self.ui_hooks.unhook()
                self.ui_hooks = None
            except:
                pass

        print("[AETHER] Plugin terminated.")

def PLUGIN_ENTRY():
    return AETHERPlugin()

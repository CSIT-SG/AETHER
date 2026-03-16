import ida_funcs, idautils, ida_name, ida_hexrays, idaapi, ida_kernwin
import threading, time, traceback
from ainalyse.function_selection import FunctionSelectionDialog
from ainalyse.__init__ import check_config_and_show_error_if_invalid, write_analysis_history
from ainalyse import load_config, validate_analysis_config, run_async_in_ida
from ainalyse.async_manager import run_in_background, use_async_worker, start_pipeline
from ainalyse.manual_gatherer import run_manual_gatherer_agent
from ainalyse.annotator import run_annotator_agent

MAX_CONTEXT_FUNCTIONS = 50

def aether_thread_function(viewer, config, selected_functions: list):
    # this doesn't look useful anymore
    selected_analyses = []
    successful_analyses = []
    print(f"[AETHER Manual Context Setter] Beginning analyses on {len(selected_functions)} functions...")
    for idx, func in enumerate(selected_functions, 1):
        try:
            print(f"[AETHER Manual Context Setter] {idx}/{len(selected_functions)}: Analysing {func['name']} [{func['address']}]...")
            config["manual_functions"] = [func]
            # it appears that the run_async_in_ida is causing crashes, we ought to use an async subroutine
            validation_success, validation_msg = run_async_in_ida(validate_analysis_config(config))
            if not validation_success:
                print(f"[AETHER Manual Context Setter] {idx}/{len(selected_functions)} Unable to analyse function: {validation_msg}")
                continue
            gatherer_success, starting_function, gatherer_output = run_async_in_ida(run_manual_gatherer_agent(config))
            annotator_output = ""
            if gatherer_success :
                print(f"[AETHER Manual Context Setter] {idx}/{len(selected_functions)}: Gatherer completed successfully. Annotator starting in 3 seconds...")
                time.sleep(3)
                annotator_result, annotator_llm_output = run_async_in_ida(run_annotator_agent(config))
                if annotator_result:
                    annotator_output = annotator_llm_output
            analysis_text = f"Function: {func['name']} [{func['address']}]\nGatherer Output:\n{gatherer_output or ''}\nAnnotator Output:\n{annotator_output or ''}\n{'-'*40}"
            selected_analyses.append(analysis_text)
            successful_analyses.append(func)
            print(f"[AETHER Manual Context Setter] {idx}/{len(selected_functions)}: Analysis complete.")
        except Exception as e:
            print(f"[AETHER Manual Context Setter] {idx}/{len(selected_functions)}: Error during analysis: {e}")
            traceback.print_exc()
    if not successful_analyses :
        ida_kernwin.warning("The analyses have totally failed. No context to set.")
        print("[AETHER Manual Context Setter] No successful analyses.")
        return
    viewer.manual_context_processed = selected_analyses.copy()
    viewer.manual_context_processed.append("\n")
    print(f"[AETHER Manual Context Setter] Manual context set with analyses of {len(successful_analyses)} functions:")
    for i, func in enumerate(successful_analyses, 1) : print(f"\t{i}:{func['name']} at [{func['address']}]")
    
def select_context_functions(viewer):
    print("[AETHER Manual Context Setter] Manual selection of context in progress...")
    try:
        ea = ida_kernwin.get_screen_ea()
        func = idaapi.get_func(ea)
        if not func:
            func_ea = next(idautils.Functions(), None)
            if func_ea is None:
                ida_kernwin.warning("No functions found in binary")
                print("[AETHER Manual Context Setter] No functions found in binary.")
                return
            func_name = ida_funcs.get_func_name(func_ea)
            func_addr = hex(func_ea)
        else:
            func_name = ida_funcs.get_func_name(func.start_ea)
            func_addr = hex(func.start_ea)
    except Exception:
        ida_kernwin.warning("Unable to get current function address.")
        print("[AETHER Manual Context Setter] Unable to get current function address.")
        return
    dlg = FunctionSelectionDialog(func_name, func_addr, "Manually select binary functions as Context", parent=viewer.parent, onlyTopLevel = True)
    if not dlg.exec_() : return

    selected_funcs = dlg.get_selected_functions()
    
    if not selected_funcs:
        ida_kernwin.warning("No functions selected.")
        print("[AETHER Manual Context Setter] No functions selected.")
        return
    if len(selected_funcs) > MAX_CONTEXT_FUNCTIONS:
        ida_kernwin.warning(f"You selected {len(selected_funcs)} functions, but the limit is {MAX_CONTEXT_FUNCTIONS} to prevent exceeding the AI context window.\n\nTruncating to the first {MAX_CONTEXT_FUNCTIONS} functions.")
        print(f"[AETHER Manual Context Setter] Truncated selection from {len(selected_funcs)} to {MAX_CONTEXT_FUNCTIONS}.")
        selected_funcs = selected_funcs[:MAX_CONTEXT_FUNCTIONS]

    viewer.manual_context = selected_funcs
    if (not viewer.manual_context) :
        ida_kernwin.warning("No functions selected.")
        print("[AETHER Manual Context Setter] No functions selected.")
        return
    if (len(viewer.manual_context) == 1) : print(f"[AETHER Manual Context Setter] 1 function selected for context.")
    else : print(f"[AETHER Manual Context Setter] {len(viewer.manual_context)} functions selected for context.")
    viewer._refresh_context_pills()
    print(f"[AETHER Manual Context Setter] {len(viewer.manual_context)} selected functions for analysis.")
    # config = load_config()
    # if not check_config_and_show_error_if_invalid(config):
    #     print("[AETHER Manual Context Setter] Configuration error, please relook at chatbot config.")
    #     return
    # config["fast_mode"] = True
    # config["custom_user_prompt"] = ""
    # print(f"[AETHER Manual Context Setter] Beginning analyses on {len(viewer.manual_context)} functions...")
    # run_in_background(aether_thread_function, viewer, config, viewer.manual_context)
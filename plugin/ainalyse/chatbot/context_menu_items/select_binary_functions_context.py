import ida_kernwin, idautils, idaapi, ida_funcs

from ainalyse.function_selection import FunctionSelectionDialog

class SelectBinaryFunctionsContext() :
    def __init__(self) : pass

    @staticmethod
    def get_current_function_name(show_warning = False) :
        """Returns the current function information in the format function_name, function_address, flag. If flag is false, function_name and function_address are invalid; else carry on as per normal"""
        try :
            ea = ida_kernwin.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func :
                func_ea = next(idautils.Functions(), None)
                if func_ea is None :
                    if (show_warning) :
                        ida_kernwin.warning("No functions found in binary")
                        print("[AETHER Manual Context Setter] No functions found in binary.")
                    return -1 ,-1, False
                func_name = ida_funcs.get_func_name(func_ea)
                func_addr = hex(func_ea)
            else :
                func_name = ida_funcs.get_func_name(func.start_ea)
                func_addr = hex(func.start_ea)
        except Exception :
            if (show_warning) :
                ida_kernwin.warning("Unable to get current function address.")
                print("[AETHER Manual Context Setter] Unable to get current function address.")
            return -1, -1, False
        return func_name, func_addr, True

    @staticmethod
    def _select_binary_functions_context(CBController) :
        """Prompts the user to manually select binary functions to add into manual context"""
        print("[AETHER Manual Context Setter] Manual selection of context in progress...")
        func_name, func_addr, flag = SelectBinaryFunctionsContext.get_current_function_name(show_warning = True)
        if (not flag) : return
        dlg = FunctionSelectionDialog(func_name, func_addr, "Manually select binary functions as Context", parent=CBController.parent, onlyTopLevel = True)
        if not dlg.exec_() : return

        CBController.manual_context = dlg.get_selected_functions()
        if (not CBController.manual_context) :
            ida_kernwin.warning("No functions selected.")
            print("[AETHER Manual Context Setter] No functions selected.")
            return
        if (len(CBController.manual_context) == 1) : print(f"[AETHER Manual Context Setter] 1 function selected for context.")
        else : print(f"[AETHER Manual Context Setter] {len(CBController.manual_context)} functions selected for context.")
        CBController._refresh_context_pills()
        print(f"[AETHER Manual Context Setter] {len(CBController.manual_context)} selected functions for analysis.")

    @staticmethod
    def _settle_manual_context(CBController) :
        """Converts the manual context into a parsable string for sending to LLM"""
        if (len(CBController.manual_context) == 0) : return ""
        prepend = "=" * 40 +"\nVERY IMPORTANT: THE FOLLOWING WILL BE A LIST OF FUNCTIONS YOU MUST HEAVILY CONSIDER, I WANT THESE FUNCTIONS TO CONSTANTLY BE IN YOUR CLANKER MIND AS YOU PROCESS THE PROMPTS; GET THEIR ANALYSES OUT AND THINK:\n"
        for f in CBController.manual_context : prepend += f"\t- ANALYSE THE FUNCTION: {f['name']} at [{f['address']}]\n"
        prepend += "END OF FUNCTION LIST. FROM THIS POINT ONWARDS, THE FOLLOWING AFTER THIS WILL BE THE USER'S PROMPT AND YOU MUST, I REPEAT, I INSIST, AND I DEMAND, THAT YOU, WHILE PROCESSING EVERYTHING, KEEP THE AFOREMENTIONED LIST OF FUNCTIONS IN MIND. NOW FLEE!\n"
        prepend += "=" * 40 + "\n\n"
        return prepend
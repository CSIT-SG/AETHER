import asyncio
import os
import time
import traceback

import ida_bytes
import ida_hexrays
import ida_kernwin
import ida_name
import idaapi
from PyQt5 import QtWidgets

from ainalyse.async_manager import run_async_in_ida, run_in_background
from ainalyse.struct_creator.struct_gatherer import run_gatherer_agent
from ainalyse.struct_creator.struct_annotator import run_annotator_agent
from ainalyse.struct_creator.struct_identifier import run_identifier_agent
from ainalyse.struct_creator.struct_creator import run_creator_agent
from ainalyse import load_config
from .tools import declare_c_struct

def run_struct_pipeline(vdui,variable) -> bool:
    """
    Run the Struct Creator pipeline asynchronously.
    Uses IDA's execute_sync for thread-safe operations.
    """
    config = load_config()

    start_time = time.perf_counter()
    try:
        var_container = {}
        def retrieve_var_name():
            if isinstance(variable, ida_hexrays.lvar_t):
                var_container['name'] = variable.name
                var_container['type'] = "Local"
            elif isinstance(variable, ida_hexrays.cexpr_t):
                # For globals, we get the name from the address
                var_container['name'] = ida_name.get_name(variable.obj_ea)
                var_container['type'] = "Global"
            else:
                print("[Struct Creator] Unknown variable type passed to pipeline.")
                return False
        ida_kernwin.execute_sync(retrieve_var_name, ida_kernwin.MFF_WRITE)
        var_name = var_container['name']
        var_type = var_container['type']
        print(f"[Struct Creator] Starting pipeline for variable: {var_name}")
        gatherer_success, starting_function, gatherer_output = run_async_in_ida(run_gatherer_agent(config,var_name))

        if gatherer_success:
            print("[AETHER] Gatherer completed successfully. Waiting 3 seconds before starting annotator...")
            time.sleep(3)
            identifier_result, identifier_llm_output, sub_graph, declared_struct = run_async_in_ida(run_identifier_agent(config,var_name))

            created_struct = set()

            for (name, size) in declared_struct:
                def _declare_c_struct_sync():
                    try:
                        declare_c_struct(name,[],size)
                        return True
                    except Exception as e:
                        print(f"[AETHER] Error creating type {struct_name}: {e}")
                        return False 
                ida_kernwin.execute_sync(_declare_c_struct_sync, ida_kernwin.MFF_WRITE)
                created_struct.add(name)

            print(sub_graph)
            struct_list = list(sub_graph.keys())
            for s in struct_list:
                if not s in created_struct:
                    def _declare_c_struct_sync1():
                        try:
                            declare_c_struct(s,[],0)
                            return True
                        except Exception as e:
                            print(f"[AETHER] Error creating type {struct_name}: {e}")
                            return False 

                    ida_kernwin.execute_sync(_declare_c_struct_sync1, ida_kernwin.MFF_WRITE)
                    created_struct.add(name)

            for struct_name,size in declared_struct[-1::-1]:
                print(f"[AETHER] Calling Annotator for {struct_name}")
                if not struct_name in sub_graph:
                    print(f"[AETHER] Error: {struct_name} not in sub_graph")
                    continue
                annotator_result, annotator_llm_output, comment_dict = run_async_in_ida(run_annotator_agent(config,struct_name,sub_graph[struct_name],struct_list))
                print("[AETHER] Annotator completed successfully. Waiting 3 seconds before starting Creator...")
                
                creator_result, creator_llm_output = run_async_in_ida(run_creator_agent(config,struct_name,sub_graph[struct_name],struct_list,comment_dict))
                if annotator_result:
                    annotator_output = annotator_llm_output
                    #print(annotator_output)

        elapsed_time = time.perf_counter() - start_time
        end_text = f"[Struct Creator] Pipeline completed successfully in {elapsed_time:.2f} seconds"
        print(end_text)
        return True

    except Exception as e:
        elapsed_time = time.perf_counter() - start_time
        error_message = str(e)
        print(f"[Struct Creator] Pipeline error after {elapsed_time:.2f} seconds: {error_message}")
        tb_str = traceback.format_exc()

        return False


class StructCreationHandler(ida_kernwin.action_handler_t):
    """Action handler for Struct Creator plugin."""
    def __init__(self, asyncio_thread=None):
        ida_kernwin.action_handler_t.__init__(self)
        self.asyncio_thread = asyncio_thread

    def activate(self, ctx):

        try:
            # Get the current pseudocode widget
            widget = idaapi.get_current_widget()
            vdui = ida_hexrays.get_widget_vdui(widget)
            if not vdui:
                print("[Struct Creator] Please run this plugin with the cursor in Pseudocode view.")
                return 1

            # Refresh the vdui to ensure its state is synchronized with the view.
            vdui.refresh_ctext()

            # The item under the cursor is a ctree_item_t
            item = vdui.item

            # If get_global_var() returns an object, we have a global variable.
            if item.citype == ida_hexrays.VDI_EXPR and item.e.op == ida_hexrays.cot_obj:
                var_address = item.e.obj_ea
                var_name = ida_name.get_name(var_address)

                flags = idaapi.get_flags(var_address)

                if not ida_bytes.is_code(flags):

                    print("--- Global Variable Info ---")
                    print(f"Name: {var_name}")
                    print(f"Address: {var_address:#x}")
                    print("----------------------------")

                    run_in_background(run_struct_pipeline, vdui, item.e)
                else:
                    print("[Struct Creator] This global variable is found in the code section.")
            else:
                # If get_global_var() returns None, try to get a local variable.
                # item.get_lvar() is the most reliable way to do this.
                lvar = item.get_lvar()

                if lvar:
                    # If get_lvar() returns an object, we have our variable.
                    var_name = lvar.name
                    stack_offset = lvar.get_stkoff()

                    print("--- Local Variable Info ---")
                    print(f"Name: {var_name}")
                    print(f"Stack Offset (Address): {stack_offset:#x}")
                    print("---------------------------")

                    run_in_background(run_struct_pipeline,vdui,lvar)
                else:
                    print("[Struct Creator] The cursor is not on a local or global variable.")

        except Exception:
            print(f"[Struct Creator] An error occurred: {traceback.format_exc()}")
        return 1

    def update(self, ctx):
        """Update the action's availability."""
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET

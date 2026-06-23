import os
from typing import Dict, Set

import ida_kernwin

from ainalyse.ssl_helper import create_openai_client_with_custom_ca

from .parser import parse_ai_decomp_response_by_address
from .storage import load_ai_decomp, save_ai_decomp
from .viewer import AI_DECOMP_VIEW_TITLE, g_ai_decomp_viewers

# Use lazy initialization to avoid circular import
VERBOSE_LOG_PATH = None

def _init_verbose_log_path():
    """Initialize verbose log path lazily to avoid circular imports"""
    global VERBOSE_LOG_PATH
    if VERBOSE_LOG_PATH is None:
        from ainalyse import get_data_directory
        data_dir = get_data_directory()
        VERBOSE_LOG_PATH = os.path.join(data_dir, "verbose.txt")

def check_and_save_new_decompilations(decompilations: Dict[str, str], already_saved: Set[str]) -> None:
    """Check for new decompilations and save them to netnode if not already saved."""
    for func_addr, decomp_code in decompilations.items():
        should_save = False
        
        if func_addr not in already_saved:
            should_save = True
            already_saved.add(func_addr)
            print(f"[AETHER] [AI Decomp] [Real-time] Found new AI decompilation for {func_addr}")
        else:
            existing_decomp = load_ai_decomp(func_addr)
            if existing_decomp and len(decomp_code) > len(existing_decomp) + 50:
                should_save = True
                print(f"[AETHER] [AI Decomp] [Real-time] Updated AI decompilation for {func_addr} ({len(existing_decomp)} -> {len(decomp_code)} chars)")
            elif not existing_decomp:
                should_save = True
                print(f"[AETHER] [AI Decomp] [Real-time] Retrying save for {func_addr} (no existing data found)")
        
        if should_save:
            if save_ai_decomp(func_addr, decomp_code):
                print(f"[AETHER] [AI Decomp] [Real-time] Successfully saved AI decompilation for {func_addr}")
                
                def _update_viewer_for_addr():
                    viewer_instance = g_ai_decomp_viewers.get(AI_DECOMP_VIEW_TITLE)
                    if (viewer_instance and 
                        viewer_instance.current_func_addr and
                        viewer_instance.current_func_addr.lower() == func_addr.lower()):
                        viewer_instance.SetGenerating(False)
                        viewer_instance.UpdateDisplay()
                try:
                    ida_kernwin.execute_sync(_update_viewer_for_addr, ida_kernwin.MFF_WRITE)
                except Exception as e:
                    print(f"[AETHER] [AI Decomp] [Real-time] Error updating viewer: {e}")
            else:
                print(f"[AETHER] [AI Decomp] [Real-time] Failed to save AI decompilation for {func_addr}")

async def stream_and_save_ai_decompilation(config: dict, ai_decomp_prompt: str, context: str, functions_list_str: str, use_prompt_b: bool = False) -> bool:
    """Handles the core logic of streaming from LLM and saving results."""
    _init_verbose_log_path()  # Initialize path lazily to avoid circular imports
    
    api_key = config["OPENAI_API_KEY"]
    model = config["AI_DECOMP_MODEL"]
    base_url = config["OPENAI_BASE_URL"]
    extra_body = config.get("OPENAI_EXTRA_BODY", {})
    custom_ca_cert_path = config.get("CUSTOM_CA_CERT_PATH", "")
    client_cert_path = config.get("CLIENT_CERT_PATH", "")
    client_key_path = config.get("CLIENT_KEY_PATH", "")

    if use_prompt_b:
        context += """

===

# Important Reminders

Begin your response with the thinking and all its stages!
You must rename local variables and arguments to meaningful names, **I don't want to see remanining v1s, v2s, a1s, qword_91383.**
You will rename local variables to meaningful names.
You need to have START_THINK and END_THINK and substantiate your changes based on evidence.
Use inferred structs in your rewritten code.
Remember, I cannot emphasise this enough, each and every function needs to be enclosed like so:

```0xaddress
// thinking
// rewritten code with comments and renamed and structs
```

/no_think
"""

    try:
        with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
            vf.write("\n--- AI Decompilation Prompt ---\n")
            vf.write(ai_decomp_prompt)
            vf.write("\n--- AI Decompilation Context ---\n")
            vf.write(context)
            vf.write("\n--- Functions List ---\n")
            vf.write(functions_list_str)
            vf.write("\n--- END AI Decompilation Input ---\n")
    except Exception as e:
        print(f"[AETHER] [AI Decomp] Error writing to verbose.txt: {e}")

    print(f"[AETHER] [AI Decomp] Requesting AI decompilation from LLM for functions: {functions_list_str}")

    try:
        client = create_openai_client_with_custom_ca(api_key, base_url, custom_ca_cert_path, client_cert_path, client_key_path)
        
        request_params = {
            "model": model,
            "messages": [
                {"role": "system", "content": ai_decomp_prompt},
                {"role": "user", "content": context}
            ],
            "max_tokens": 32768,
            "temperature": 0.5,
            "stream": True
        }
        
        if extra_body:
            request_params["extra_body"] = extra_body
        
        stream = client.chat.completions.create(**request_params)
        
        full_response = ""
        already_saved: Set[str] = set()
        
        print("[AETHER] [AI Decomp] Streaming AI decompilation response...")
        
        for chunk in stream:
            content = getattr(chunk.choices[0].delta, "content", None)
            if content is None:
                continue
            full_response += content
            current_decompilations = parse_ai_decomp_response_by_address(full_response)
            check_and_save_new_decompilations(current_decompilations, already_saved)

        print(f"\n[AETHER] [AI Decomp] Streaming completed. Response length: {len(full_response)} characters")
        
        final_decompilations = parse_ai_decomp_response_by_address(full_response)
        
        print(f"[AETHER] [AI Decomp] Final processing: Ensuring all {len(final_decompilations)} functions are saved with latest content")
        for func_addr_final, decomp_code_final in final_decompilations.items():
            if save_ai_decomp(func_addr_final, decomp_code_final):
                print(f"[AETHER] [AI Decomp] Final save: Successfully saved complete AI decompilation for {func_addr_final} ({len(decomp_code_final)} chars)")
            else:
                print(f"[AETHER] [AI Decomp] Final save: Failed to save AI decompilation for {func_addr_final}")
        
        try:
            with open(VERBOSE_LOG_PATH, "a", encoding="utf-8") as vf:
                vf.write("\n--- AI Decompilation LLM Response ---\n")
                vf.write(full_response)
                vf.write("\n--- END AI Decompilation Response ---\n")
                vf.write("\n--- AI Decompilation Summary ---\n")
                vf.write(f"Total functions processed: {len(final_decompilations)}\n")
                vf.write(f"Function addresses: {list(final_decompilations.keys())}\n")
                vf.write("--- END AI Decompilation Summary ---\n")
        except Exception as e:
            print(f"[AETHER] [AI Decomp] Error writing LLM response to verbose.txt: {e}")

        print(f"[AETHER] [AI Decomp] AI decompilation completed successfully. Processed {len(final_decompilations)} functions.")
        return True

    except Exception as e:
        print(f"[AETHER] [AI Decomp] Error during streaming: {e}")
        return False
    finally:
        def _final_update():
            viewer_instance = g_ai_decomp_viewers.get(AI_DECOMP_VIEW_TITLE)
            if viewer_instance:
                viewer_instance.SetGenerating(False)
                viewer_instance.UpdateDisplay()
        ida_kernwin.execute_sync(_final_update, ida_kernwin.MFF_WRITE)

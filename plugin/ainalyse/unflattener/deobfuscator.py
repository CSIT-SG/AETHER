import os
from datetime import datetime
import time
from urllib.parse import urlparse

import ida_kernwin
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
import tiktoken

from ainalyse.ssl_helper import create_openai_client_with_custom_ca
from .extractor import extract_and_clean_code, clean_c_code
from .viewer import AI_DEOBFS_VIEW_TITLE, g_ai_deobfs_viewers
from .deobfuscator_core import check_and_save_new_deobfuscations


# File paths
DEOBFUSCATOR_PROMPT_FILE = os.path.join(os.path.dirname(__file__), "..", "prompts", "deobfuscator-prompt.txt")
DEOBFUSCATOR_CHECK_FILE = os.path.join(os.path.dirname(__file__), "..", "prompts", "deobfuscator-check.txt")
DEOBFUSCATOR_LABEL_FILE = os.path.join(os.path.dirname(__file__), "..", "prompts", "deobfuscator-label.txt")


def update_display_error(error: str):
    viewer_instance = g_ai_deobfs_viewers.get(AI_DEOBFS_VIEW_TITLE)
    if viewer_instance:
        viewer_instance.SetError(error)
        viewer_instance.UpdateDisplay()

def call_openai_deobfuscator(system_prompt: str, user_prompt: str, api_key: str, model: str, base_url: str, system_prompt_at_bottom: bool, prompt_token_warning: int, extra_body: dict = None, custom_ca_cert_path: str = "", client_cert_path: str = "", client_key_path: str = "", max_tokens: int = 16384, debug: bool = False, task: str = "") -> str:
    """Call OpenAI API for deobfuscator analysis."""
    try:
        try:
            # Estimate tokens generated for user prompt
            os.environ["TIKTOKEN_CACHE_DIR"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "\encodings"
            enc = tiktoken.get_encoding("r50k_base")
            print("[AInalyse] [LLM] Estimated Tokens Generated: "+str(len(enc.encode(user_prompt + system_prompt))))
            if len(enc.encode(user_prompt + system_prompt)) > prompt_token_warning:
                print(f"[AInalyse] [LLM] Pseudo Code sent may be cut due to being too long.")
        except Exception as e:
            print(f"[AInalyse] [LLM] Error estimating tokens generated: {e}")

        client = create_openai_client_with_custom_ca(api_key, base_url, custom_ca_cert_path, client_cert_path, client_key_path, task)

        if system_prompt_at_bottom:
            messages =[{"role": "user", "content": user_prompt}, {"role": "system", "content": system_prompt}]
        else:
            messages =[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]
        request_params = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": 0.1
            }
        
        if extra_body:
            request_params["extra_body"] = extra_body

        
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if debug:
            with open(f"{task}_{current_time}.txt", "w", encoding='utf-8') as outputfile:
                outputfile.write("SYSTEM PROMPT:\n" + system_prompt)
                outputfile.write("\n\nUSER PROMPT:\n" + user_prompt)
                outputfile.write("\n\nRESPONSE:\n")
        response = client.chat.completions.create(**request_params)
        if debug:
            with open(f"{task}_{current_time}.txt", "a", encoding='utf-8') as outputfile:
                outputfile.write(response.choices[0].message.content.strip())
        return response.choices[0].message.content.strip()
    except Exception as e:
        if debug:
            with open(f"{task}_{current_time}.txt", "a", encoding='utf-8') as outputfile:
                outputfile.write(f"{e}")
        print(f"[AInalyse] [AI Unflatten] Error calling OpenAI API: {e}")
        return ""


def strip_and_reformat_pseudocode_for_deobfuscator(pseudocode: str) -> str:
    """Clean pseudocode for deobfuscator analysis."""
    import re
    lines = pseudocode.splitlines()
    result = []
    line_re = re.compile(r'^\s*/\*\s*line:\s*(\d+)(?:,\s*address:\s*(0x[0-9a-fA-F]+))?\s*\*/\s*(.*)$')
    
    for line in lines:
        if line.strip().startswith('cannotComment|') or re.match(r'^\s*0x[0-9a-fA-F]+\|', line):
            result.append(line)
            continue
            
        m = line_re.match(line)
        if m:
            address = m.group(2)
            code = m.group(3)
            if address:
                result.append(f"{address}| {code}")
            else:
                result.append(f"cannotComment| {code}")
        else:
            if line.strip():
                result.append(f"cannotComment| {line}")
            else:
                result.append(line)
    return "\n".join(result)

async def run_deobfuscator(config: dict, current_func_name: str, current_func_addr: str) -> bool:
    """Function for running unflattening."""

    start_time = time.time()
    
    server_url = config["MCP_SERVER_URL"]
    api_key = config["OPENAI_API_KEY"]
    # Use SINGLE_ANALYSIS_MODEL for deobfuscator analysis, fall back to OPENAI_MODEL if not set
    model = config.get("SINGLE_ANALYSIS_MODEL") or config["OPENAI_MODEL"]
    base_url = config["OPENAI_BASE_URL"]
    system_prompt_at_bottom = config.get("SYSTEM_PROMPT_AT_BOTTOM", False)
    prompt_token_warning = config.get("PROMPT_TOKEN_WARNING", 64000)
    extra_body = config.get("OPENAI_EXTRA_BODY", {})
    custom_ca_cert_path = config.get("CUSTOM_CA_CERT_PATH", "")
    client_cert_path = config.get("CLIENT_CERT_PATH", "")
    client_key_path = config.get("CLIENT_KEY_PATH", "")
    debug = config.get("DEBUG", False)
    max_tokens = config.get("DEOBFUSCATOR_MAX_TOKENS", 16384)

    viewer_instance = g_ai_deobfs_viewers.get(AI_DEOBFS_VIEW_TITLE)
    if viewer_instance:
        viewer_instance.SetGenerating(True)
        viewer_instance.UpdateDisplay()
        viewer_instance.Show(AI_DEOBFS_VIEW_TITLE)

    if urlparse(server_url).scheme not in ("http", "https"):
        print("[AInalyse] [AI Unflatten] Error: MCP_SERVER_URL must start with http:// or https://")
        return False

    if not api_key:
        print("[AInalyse] [AI Unflatten] Error: OPENAI_API_KEY not set in config.")
        return False

    print(f"[AInalyse] [AI Unflatten] Using model: {model}")

    # Test MCP connection first before proceeding
    from ainalyse import test_mcp_connection
    print("[AInalyse] [AI Unflatten] Testing MCP connection...")
    mcp_success, mcp_msg = await test_mcp_connection(server_url)
    if not mcp_success:
        print(f"[AInalyse] [AI Unflatten] MCP connection failed: {mcp_msg}")
        update_display_error(f"[AInalyse] [AI Unflatten] MCP connection failed: {mcp_msg}")
        return False
    print("[AInalyse] [AI Unflatten] MCP connection test successful")
    try:
        # Load unflatten prompt file
        with open(DEOBFUSCATOR_PROMPT_FILE, "r", encoding="utf-8") as f:
            system_prompt = f.read()
    except FileNotFoundError:
        print(f"[AInalyse] [AI Unflatten] Error: Unflatten Prompt file not found at {DEOBFUSCATOR_PROMPT_FILE}")
        update_display_error(f"[AInalyse] [AI Unflatten] Error: Unflatten Prompt file not found at {DEOBFUSCATOR_PROMPT_FILE}")
        return False
    try:
        # Load check prompt file
        with open(DEOBFUSCATOR_CHECK_FILE, "r", encoding="utf-8") as f:
            deobfuscator_check = f.read()
    except FileNotFoundError:
        print(f"[AInalyse] [AI Unflatten] Error: Check Prompt file not found at {DEOBFUSCATOR_CHECK_FILE}")
        update_display_error(f"[AInalyse] [AI Unflatten] Error: Check Prompt file not found at {DEOBFUSCATOR_CHECK_FILE}")
        return False
    try:
        # Load label prompt file
        with open(DEOBFUSCATOR_LABEL_FILE, "r", encoding="utf-8") as f:
            deobfuscator_label = f.read()
    except FileNotFoundError:
        print(f"[AInalyse] [AI Unflatten] Error: Label Prompt file not found at {DEOBFUSCATOR_LABEL_FILE}")
        update_display_error(f"[AInalyse] [AI Unflatten] Error: Label Prompt file not found at {DEOBFUSCATOR_LABEL_FILE}")
        return False

    try:
        async with sse_client(server_url) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                print("[AInalyse] [AI Unflatten] Connected to MCP server.")

                # Get pseudocode for selected function
                
                pseudocode_container = {"code": ""}
                
                def _get_pseudocode_sync():
                    try:
                        from ainalyse.custom_set_cmt import custom_get_pseudocode
                        pseudocode = custom_get_pseudocode(current_func_addr)
                        if pseudocode:
                            pseudocode_container["code"] = pseudocode
                            return True
                    except Exception as e:
                        print(f"[AInalyse] [AI Unflatten] Error getting pseudocode for {current_func_addr}: {e}")
                    return False
                
                success = ida_kernwin.execute_sync(_get_pseudocode_sync, ida_kernwin.MFF_READ)
                if success and pseudocode_container["code"]:
                    pseudocode_store = strip_and_reformat_pseudocode_for_deobfuscator(pseudocode_container["code"])
                print("[AInalyse] [AI Unflatten] Requesting analysis from LLM...")

                for i in range(3):
                    # Call LLM to unflatten original pseudocode
                    llm_response = call_openai_deobfuscator(
                        system_prompt, pseudocode_store, api_key, model, base_url, system_prompt_at_bottom, prompt_token_warning,
                        extra_body, custom_ca_cert_path, client_cert_path, client_key_path, max_tokens, debug, "Unflatten"
                    )
                    if not llm_response:
                        print("[AInalyse] [AI Unflatten] No response from LLM.")
                        update_display_error("No response from LLM.")
                        return False
                    deobfuscated_code = clean_c_code(extract_and_clean_code(llm_response))
                    # Call LLM to check deobfuscated pseudocode, if doesn't match original pseudocode more than 3 times, display error message
                    llm_response = call_openai_deobfuscator(
                        deobfuscator_check, "\n\nOBFUSCATED CODE:\n" + pseudocode_store + "\n\nDEOBFUSCATED CODE:\n" + deobfuscated_code, api_key, model, base_url, system_prompt_at_bottom, prompt_token_warning,
                        extra_body, custom_ca_cert_path, client_cert_path, client_key_path, max_tokens, debug, "Check"
                    )
                    if not llm_response:
                        print("[AInalyse] [AI Unflatten] No response from LLM.")
                        update_display_error("No response from LLM.")
                        return False
                    
                    if "Deobfuscated code is not fully equivalent to obfuscated code" in llm_response:
                        if i == 2:
                            update_display_error("Error generating deobfuscated code. Please Regenerate...")
                            elapsed_time = time.time() - start_time
                            print(f"[AInalyse] [AI Unflatten] Analysis completed in {elapsed_time:.2f} seconds")
                            return False
                        else:
                            print("Deobfuscated code doesn't match obfuscated code, regenerating...")
                    else:
                        # Call LLM to label addresses on deobfuscated pseudocode
                        llm_response = call_openai_deobfuscator(
                            deobfuscator_label, "\n\nOBFUSCATED CODE:\n" + pseudocode_store + "\n\nDEOBFUSCATED CODE:\n" + deobfuscated_code, api_key,  model, base_url, system_prompt_at_bottom, prompt_token_warning,
                            extra_body, custom_ca_cert_path, client_cert_path, client_key_path, max_tokens, debug, "Label"
                        )
                        if not llm_response:
                            print("[AInalyse] [AI Unflatten] No response from LLM.")
                            update_display_error("No response from LLM.")
                            return False
                        break
                elapsed_time = time.time() - start_time
                print(f"[AInalyse] [AI Unflatten] Analysis completed in {elapsed_time:.2f} seconds")
                check_and_save_new_deobfuscations({current_func_addr:clean_c_code(extract_and_clean_code(llm_response))},set())
                viewer_instance = g_ai_deobfs_viewers.get(AI_DEOBFS_VIEW_TITLE)
                if viewer_instance:
                    viewer_instance.SetGenerating(False)
                    viewer_instance.UpdateDisplay()
                return True

    except Exception as e:
        print(f"[AInalyse] [AI Unflatten] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        update_display_error(f"{e}")
        return False

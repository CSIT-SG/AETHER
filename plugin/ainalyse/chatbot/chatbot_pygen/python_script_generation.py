import idaapi
import ida_kernwin
import idc
import idautils
import ida_funcs
import ida_hexrays
import re
import datetime
import io
import sys
import json
import threading
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import os
import ast
import types
import traceback

from ainalyse import load_config, get_data_directory
from ainalyse.async_manager import run_async_in_ida, run_in_background
from ainalyse.ssl_helper import create_openai_client_with_custom_ca
from ainalyse.custom_set_cmt import custom_get_pseudocode
from ainalyse.qt_shim import QtCore, QtGui, QtWidgets, is_deleted

# Calls that warrant a warning dialog before running
_RISKY_CALLS = {
    # Network
    "socket", "connect", "bind", "sendto", "sendall", "send",
    # Process / shell
    "subprocess", "Popen", "call", "run", "check_output", "system", "popen",
    "spawn", "execv", "execve", "execvp", "execl", "execle", "execle",
    # Filesystem – destructive
    "remove", "unlink", "rmdir", "rmtree", "shutil",
    # Dynamic code
    "eval", "compile", "__import__",
}

def _qt_obj_valid(obj) -> bool:
    try:
        return not is_deleted(obj)
    except Exception:
        return False

def _safe_chat_form_update(chat_form, text: str, is_final: bool = False) -> bool:
    # Hard gate: if shutdown has started, touching IDA C++ objects is unsafe
    if _pygen_shutting_down:
        print("[DEBUG] _safe_chat_form_update: aborted (shutting down)")
        return False

    app = QtWidgets.QApplication.instance()
    if app is None:
        print("[DEBUG] _safe_chat_form_update: aborted (no QApplication)")
        return False
    if app.closingDown():
        print("[DEBUG] _safe_chat_form_update: aborted (QApplication closing down)")
        return False
    
    # Check if form was explicitly closed
    if getattr(chat_form, "is_closed", False):
        print(f"[DEBUG] _safe_chat_form_update: aborted (form closed) id={id(chat_form)}")
        return False

    def sync_update():
        print(f"[DEBUG] _safe_chat_form_update.sync_update: starting (id={id(chat_form)})")
        if _pygen_shutting_down: # Re-check inside sync
            print("[DEBUG] _safe_chat_form_update.sync_update: aborted (shutting down)")
            return 0
        if getattr(chat_form, "is_closed", False):
            print(f"[DEBUG] _safe_chat_form_update.sync_update: aborted (form closed) id={id(chat_form)}")
            return 0
            
        # Try to find the text box. It might not be created yet if Show() was just called.
        # PluginForm.Show() is async.
        text_box = getattr(chat_form, "text_box", None)
        if text_box is None:
            print(f"[DEBUG] _safe_chat_form_update: text_box is None on chat_form id={id(chat_form)}")
            return 0
            
        if is_deleted(text_box):
            print(f"[DEBUG] _safe_chat_form_update: text_box is deleted for chat_form id={id(chat_form)}")
            return 0
            
        try:
            print(f"[DEBUG] _safe_chat_form_update: actually setting text (len={len(text)})")
            text_box.setPlainText(text)
            text_box.repaint()
            print("[DEBUG] _safe_chat_form_update.sync_update: finished successfully")
        except Exception as e:
            print(f"[-] Failed to update chat form text box: {e}")
            return 0
        return 1

    # Optimization: if already on main thread, execute directly
    if QtCore.QThread.currentThread() == app.thread():
        print(f"[DEBUG] _safe_chat_form_update: already on main thread, updating directly (id={id(chat_form)})")
        sync_update()
        return True

    # Use MFF_WRITE for all updates to ensure they are processed correctly by IDA's execute_sync.
    # MFF_FAST (0x10) is sometimes not accepted as a primary request flag for execute_sync.
    sync_flag = ida_kernwin.MFF_WRITE
    
    print(f"[DEBUG] _safe_chat_form_update: scheduling sync_update (final={is_final}, id={id(chat_form)})")
    res = ida_kernwin.execute_sync(sync_update, sync_flag)
    print(f"[DEBUG] _safe_chat_form_update: execute_sync returned {res}")
    if res == -1:
        if not (app and app.closingDown()):
            print(f"[DEBUG] _safe_chat_form_update: execute_sync failed to run for {chat_form}")
        return False
    return True

RAG_FILE = "IDA9_RAG.json"
_IAT_SEGMENT_BOUNDS = None

_chat_form_instance = None
_pygen_bg_thread = None
_pygen_shutting_down = False

def get_or_create_chat_form() -> "LLMChatForm":
    global _chat_form_instance
    if _chat_form_instance is None or getattr(_chat_form_instance, "is_closed", True):
        _chat_form_instance = LLMChatForm()
    return _chat_form_instance

def _scan_risks(source: str) -> list[str]:
    """
    Parse the script and return a list of suspicious call names found.
    Uses AST so it won't false-positive on comments or strings.
    """
    findings = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings  # will fail at exec time anyway

    for node in ast.walk(tree):
        name = None
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
        if name and name in _RISKY_CALLS:
            findings.append(name)

    return list(dict.fromkeys(findings))  # deduplicated, order-preserved

def _make_safe_os(real_os, output_dir: str):
    """
    Return an os-like module where dangerous functions raise RuntimeError.
    Safe file-creation calls are redirected under output_dir automatically.
    """
    BLOCKED = {"system", "popen", "execv", "execve", "execvp",
            "execl", "execle", "spawnl", "spawnle", "spawnv",
            "spawnve", "fork", "forkpty", "kill", "killpg"}

    def _blocked(name):
        def _f(*a, **kw):
            raise RuntimeError(
                f"os.{name}() is blocked in the IDAPython script sandbox."
            )
        _f.__name__ = name
        return _f

    proxy = types.ModuleType("os")
    proxy.__dict__.update(real_os.__dict__)          # copy everything first
    proxy.path = real_os.path                        # keep os.path intact

    for fn in BLOCKED:
        if hasattr(real_os, fn):
            setattr(proxy, fn, _blocked(fn))

    # Redirect os.remove / os.unlink to only work inside output_dir
    def _safe_remove(path):
        real_path = real_os.path.realpath(path)
        real_out  = real_os.path.realpath(output_dir)
        if not real_path.startswith(real_out):
            raise RuntimeError(
                f"os.remove() outside OUTPUT_DIR is blocked: {path}"
            )
        return real_os.remove(path)

    proxy.remove = _safe_remove
    proxy.unlink = _safe_remove
    return proxy

def cleanup_pygen():
    """Explicitly release resources during plugin teardown."""
    global _chat_form_instance, _pygen_bg_thread, _pygen_shutting_down
    _pygen_shutting_down = True  # Hard gate for all future execute_sync calls

    print("[DEBUG] cleanup_pygen: Cleaning up resources")
    try:
        if _chat_form_instance:
            if _chat_form_instance.current_query:
                _chat_form_instance.current_query.is_cancelled = True
            _chat_form_instance.is_closed = True
    except Exception:
        pass

    # Do NOT join the background thread during IDA exit. Joining can cause 
    # deadlocks if the worker is stuck in an execute_sync call waiting for 
    # the main thread (which is currently blocking on this join).
    # Since it is a daemon thread, it will be cleaned up by the OS.
    _pygen_bg_thread = None

    _chat_form_instance = None

class LLMContext:
    messages = []

    @staticmethod
    def clear():
        LLMContext.messages = []

    @staticmethod
    def add(role: str, content: str):
        data = {
            "role": role,
            "content": content
        }
        LLMContext.messages.append(data)

    @staticmethod
    def query_rag(description, num_results=3):
        rag_filepath = os.path.join(os.path.dirname(__file__), RAG_FILE)
        with open(rag_filepath, 'r') as f:
            RAG = json.load(f)

        descriptions = list(RAG.keys())

        vectorizer = TfidfVectorizer()
        tfidf_matrix = vectorizer.fit_transform(list(descriptions))

        description_vector = vectorizer.transform([description])

        similarities = cosine_similarity(description_vector, tfidf_matrix).flatten()
        scores = sorted(zip(descriptions, similarities), key=lambda x: x[1], reverse=True)

        results = []
        for i in range(num_results):
            description, score = scores[i]
            type_name = RAG[description]
            results.append((type_name, description))

        return results

class OpenRouterQuery:
    def set_system_prompt(self):
        # Identify all IDA modules that will be pre-imported
        ida_mods = sorted([m for m in sys.modules if m.startswith('ida') and sys.modules[m] is not None])
        ida_mods_str = ", ".join([f"`{m}`" for m in ida_mods])

        self.system_prompt = f"""
You are an expert IDA Pro and IDAPython developer. Your task is to write a script that accomplishes the user's objective using the IDAPython API (specifically IDA 9.0+ compatible).

The user will provide a specific objective (e.g., deobfuscating a function, decrypting strings, renaming variables based on logic, extracting data, etc.).

# Execution Environment
Your script will be executed in a pre-configured environment inside IDA Pro 9.0+.
- **Pre-imported IDA Modules:** All available IDA modules are already imported and available globally: {ida_mods_str}.
- **Common Utility Modules:** `idc`, `idautils`, `QtWidgets`, `QtCore`, `QtGui`, `sys`, `json`, `re`, `datetime`.
- **IDA 9.0+ API Standards**:
    - `ida_struct` and `ida_enum` have been removed and superseded by `ida_typeinf`. Use `ida_typeinf` for all structure and enum management. For strings use `ida_strlist`.
    - Many older APIs have moved or been renamed. Always prefer modern IDA 9.0 namespaces.
- **Safe `os` module**: A pre-imported `os` module is available. Note that dangerous calls (system, popen, fork, exec, spawn, etc.) are blocked for security.
- **File System**: A pre-defined `OUTPUT_DIR` variable is available. ALWAYS use this directory for any file output. Never hardcode absolute paths like C:\\ or /tmp/.
- **Context**: The script runs with `__name__` set to '__main__'.

Your response MUST follow these rules:
1. Provide the complete IDAPython script inside a single ```python block.
2. DO NOT use 'if __name__ == "__main__":'. Write your logic directly.
3. Use print() statements to provide verbose debugging information, showing steps taken and results found.
4. If you need information about a specific IDAPython API function, use a ```request block:
```request
Function to read bytes at an address
```
I will provide RAG-based candidates for your request.

5. When modifying the database (renaming, adding comments, etc.), ensure your logic is robust.
6. If the objective involves deobfuscation or decryption, add comments to the pseudocode or disassembly to show the recovered data.
7. Focus exclusively on the user's objective.
8. File I/O Example:
    import os
    out_path = os.path.join(OUTPUT_DIR, "extracted_strings.txt")
    with open(out_path, 'w') as f:
        f.write("...")
"""

    def __init__(self, model="qwen/qwen3-coder:exacto"):
        self.model = model
        self.set_system_prompt()
        self.is_cancelled = False

    def send(self, messages: list) -> str:
        print("[DEBUG] OpenRouterQuery.send: method started")
        try:
            if self.is_cancelled:
                print("[DEBUG] OpenRouterQuery.send: cancelled at start")
                return "Operation cancelled."

            config = load_config()
            print(f"[DEBUG] OpenRouterQuery.send: config loaded, API_KEY len={len(config.get('OPENAI_API_KEY', ''))}")
            
            client = create_openai_client_with_custom_ca(
                config["OPENAI_API_KEY"],
                config["OPENAI_BASE_URL"],
                config.get("CUSTOM_CA_CERT_PATH", ""),
                config.get("CLIENT_CERT_PATH", ""),
                config.get("CLIENT_KEY_PATH", ""),
                feature="python_script_generation"
            )
            print("[DEBUG] OpenRouterQuery.send: OpenAI client created")

            # Detailed debug logging
            log_dir = os.path.join(get_data_directory(), "chatbot", "debug")
            os.makedirs(log_dir, exist_ok=True)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = os.path.join(log_dir, f"pygen_prompt_{timestamp}.json")

            try:
                with open(log_file, 'w', encoding='utf-8') as f:
                    json.dump(messages, f, indent=4)
                print(f"[DEBUG] Python script generation prompt logged to {log_file}")
            except Exception as e:
                print(f"[DEBUG] Failed to log prompt: {e}")

            # FOR DEBUG/HISTORY
            try:
                with open('convo.json', 'w') as f:
                    json.dump(LLMContext.messages, f, indent=4)
            except Exception:
                pass

            if self.is_cancelled:
                print("[DEBUG] OpenRouterQuery.send: cancelled before completions.create")
                return "Operation cancelled."

            model_name = config.get("OPENAI_MODEL", "gpt-4")
            print(f"[DEBUG] OpenRouterQuery.send: calling completions.create for model {model_name}...")
            
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                max_tokens=config.get("CHATBOT_MAX_TOKENS", 65536),
                temperature=0.7,
                timeout=60.0 # Prevent indefinite hangs
            )
            print("[DEBUG] OpenRouterQuery.send: completions.create returned")

            if self.is_cancelled:
                print("[DEBUG] OpenRouterQuery.send: cancelled after completions.create")
                return "Operation cancelled."

            if hasattr(response, 'error') and len(response.error) > 0:
                print(f"[DEBUG] response.error: {response.error}")
                error_message = response.error['message']
                error_code = response.error['code']
                return f"LLM Error: {error_message} (Code: {error_code})"

            message = response.choices[0].message
            content = getattr(message, "content", "") or ""
            
            # Handle reasoning content if present (common in R1 models)
            reasoning = ""
            for attr in ["reasoning", "reasoning_content", "reasoning_details"]:
                if hasattr(message, attr):
                    val = getattr(message, attr)
                    if val:
                        reasoning = val
                        break
            
            response_text = content.strip()
            
            if not response_text and reasoning:
                response_text = f"> Thought: {reasoning}"
                
            print(f"[DEBUG] OpenRouterQuery.send: response_text len={len(response_text)}")
            
            if not response_text:
                print("[DEBUG] OpenRouterQuery.send: empty response from LLM")
                LLMContext.add("assistant", "No response from LLM...")
                return "Error: No response from LLM."
            
            LLMContext.add("assistant", response_text)

            # Log the response as well
            log_dir = os.path.join(get_data_directory(), "chatbot", "pygen_output")
            os.makedirs(log_dir, exist_ok=True)
            resp_file = os.path.join(log_dir, f"pygen_response_{timestamp}.txt")
            try:
                with open(resp_file, 'w', encoding='utf-8') as f:
                    f.write(response_text)
            except Exception:
                pass

            return response_text

        except Exception as e:
            msg = f"Unexpected Error during script generation: {str(e)}"
            print(f"[-] {msg}")
            import traceback
            traceback.print_exc()
            return msg

    def send_first_prompt_async(self, user_prompt, target_func_name, chat_form):
        print(f"[DEBUG] send_first_prompt_async started for {target_func_name}")
        
        # Wait for chat_form to be fully initialized if needed (widgets created)
        ui_ready = False
        for i in range(50): # up to 5s
            if getattr(chat_form, "text_box", None) is not None:
                ui_ready = True
                break
            if self.is_cancelled: 
                print("[DEBUG] send_first_prompt_async: cancelled during UI wait")
                return
            if i % 10 == 0:
                print(f"[DEBUG] send_first_prompt_async: waiting for UI... (attempt {i})")
            time.sleep(0.1)
        
        if not ui_ready:
            print("[WARN] send_first_prompt_async: UI never became ready (text_box is None)")

        try:
            if self.is_cancelled: return

            app = QtWidgets.QApplication.instance()
            
            # --- PHASE 0: Global Environment Prep (Main Thread) ---
            result = {}
            def prep_env():
                result['is_pe'] = idaapi.get_file_type_name().startswith("Portable executable")
                _ = DeobfuscateHandler.is_iat_address(0)
                return 1

            ida_kernwin.execute_sync(prep_env, ida_kernwin.MFF_READ)
            is_pe = result.get('is_pe', False)

            # --- PHASE 1: Data Gathering (Background) ---
            _safe_chat_form_update(chat_form, f"[+] Resolving target function: {target_func_name}...")
            
            result = {}
            def get_target_ea():
                result['ea'] = idc.get_name_ea_simple(target_func_name)
                return 1

            ida_kernwin.execute_sync(get_target_ea, ida_kernwin.MFF_READ)
            target_ea = result.get('ea', idaapi.BADADDR)
            
            if target_ea == idaapi.BADADDR:
                _safe_chat_form_update(chat_form, f"Error: Could not find function {target_func_name}")
                return

            if self.is_cancelled or (app and app.closingDown()): return

            _safe_chat_form_update(chat_form, f"[+] Tracing call chain for {target_func_name}...")
            call_chain = DeobfuscateHandler.get_call_chain(target_ea, is_pe, self)
            
            if self.is_cancelled or (app and app.closingDown()): return

            # 3. Decompile each function
            func_pseudocode_map = {}
            for i, func_ea in enumerate(call_chain):
                if self.is_cancelled or (app and app.closingDown()): return

                result = {}
                def get_info(ea=func_ea):           # default arg captures current ea
                    result['name'] = idc.get_func_name(ea)
                    result['pseudo'] = custom_get_pseudocode(ea)
                    return 1

                ida_kernwin.execute_sync(get_info, ida_kernwin.MFF_READ)
                name      = result.get('name', '')
                pseudocode = result.get('pseudo', '')

                _safe_chat_form_update(chat_form, f"[+] Decompiling function {i+1}/{len(call_chain)}: {name}...")
                if pseudocode:
                    func_pseudocode_map[func_ea] = pseudocode

            if self.is_cancelled or (app and app.closingDown()): return

            _safe_chat_form_update(chat_form, "[+] Preparing final prompt for LLM...")
            prompt = user_prompt
            prompt += f"\nObjective: Write an IDAPython script for function {target_func_name} and its logic chain.\n\n"
            prompt += "--- Decompiled Functions in Chain ---\n"
            
            for func_ea in call_chain:
                if func_ea not in func_pseudocode_map: continue
                prompt += f"```{hex(func_ea)}\n{func_pseudocode_map[func_ea]}\n```\n"

                result = {}
                def get_refs_as_strings(ea=func_ea):
                    refs = DeobfuscateHandler.get_global_references(ea)
                    result['refs'] = [f"{hex(r)}: {idc.get_name(r)}" for r in refs]
                    return 1

                ida_kernwin.execute_sync(get_refs_as_strings, ida_kernwin.MFF_READ)
                refs_list = result.get('refs', [])
                if refs_list:
                    prompt += "\n".join(refs_list) + "\n"

            # --- PHASE 2: LLM Call ---
            _safe_chat_form_update(chat_form, "Thinking...")
            LLMContext.add("system", self.system_prompt)
            LLMContext.add("user", prompt)

            print("[DEBUG] send_first_prompt_async: calling self.send")
            response = self.send(LLMContext.messages)
            print(f"[DEBUG] send_first_prompt_async: self.send returned {len(response) if response else 0} chars")

            if not self.is_cancelled and not (app and app.closingDown()):

                _safe_chat_form_update(chat_form, response, is_final=True)
                
        except Exception as e:
            err_msg = f"Critical Error in async prompt handler: {str(e)}"
            print(f"[-] {err_msg}")
            import traceback
            traceback.print_exc()
            if not self.is_cancelled:
                _safe_chat_form_update(chat_form, err_msg, is_final=True)
        print("[DEBUG] send_first_prompt_async finished")

    def send_next_prompt_async(self, additional_comments, chat_form):
        print("[DEBUG] send_next_prompt_async started")
        try:
            if self.is_cancelled:
                print("[DEBUG] send_next_prompt_async: already cancelled")
                return

            _safe_chat_form_update(chat_form, "Regenerating...")
            if len(additional_comments) > 0:
                LLMContext.add("user", additional_comments)

            print("[DEBUG] send_next_prompt_async: calling self.send")
            response = self.send(LLMContext.messages)
            print(f"[DEBUG] send_next_prompt_async: self.send returned {len(response) if response else 0} chars")
            if not self.is_cancelled:
                _safe_chat_form_update(chat_form, response, is_final=True)
                print(f"[+] Regenerated")
        except Exception as e:
            err_msg = f"Critical Error in async regen handler: {str(e)}"
            print(f"[-] {err_msg}")
            import traceback
            traceback.print_exc()
            if not self.is_cancelled:
                _safe_chat_form_update(chat_form, err_msg, is_final=True)
        print("[DEBUG] send_next_prompt_async finished")

class LLMChatForm(ida_kernwin.PluginForm):
    FORM_NAME = "AETHER IDAPython Generation"
    CHATBOT_WINDOW_NAME = "AETHER Chatbot V2"

    def __init__(self):
        super().__init__()
        self.text_box = None
        self.comment_input = None
        self.current_query = None
        self.is_closed = False

    def OnCreate(self, form):
        # Called when the form is created
        self.is_closed = False
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        layout = QtWidgets.QVBoxLayout()

        # --- Text area (read-only)
        self.text_box = QtWidgets.QPlainTextEdit()
        self.text_box.setReadOnly(True)
        # Use a monospaced font
        font = QtGui.QFont("Courier New", 10)
        self.text_box.setFont(font)
        self.text_box.setPlainText("Initializing data gathering...")
        layout.addWidget(self.text_box)

        # --- Comment input field (for user input)
        comment_layout = QtWidgets.QHBoxLayout()
        comment_label = QtWidgets.QLabel("Additional LLM Prompts:")
        self.comment_input = QtWidgets.QLineEdit()
        self.comment_input.setPlaceholderText("Type additional comments here...")
        self.comment_input.returnPressed.connect(self.on_regen_code)
        comment_layout.addWidget(comment_label)
        comment_layout.addWidget(self.comment_input)
        layout.addLayout(comment_layout)

        # --- Buttons at the bottom
        button_layout = QtWidgets.QHBoxLayout()
        self.run_button = QtWidgets.QPushButton("Run Code")
        self.regen_button = QtWidgets.QPushButton("Regenerate Code")

        button_layout.addWidget(self.run_button)
        button_layout.addWidget(self.regen_button)
        layout.addLayout(button_layout)

        # --- Connect actions
        self.run_button.clicked.connect(self.on_run_code)
        self.regen_button.clicked.connect(self.on_regen_code)

        self.parent.setLayout(layout)

    def on_run_code(self):
        global _pygen_shutting_down
        _pygen_shutting_down = False # Ensure updates are allowed
        
        ida_kernwin.info("Run Code clicked!")
        text = self.get_text()

        if not text:
            print("[-] No code to run.")
            return

        # Use more robust block detection
        python_codes = re.findall(r"```(?:python|py)\s*\n([\s\S]*?)\n```", text, re.IGNORECASE)
        if len(python_codes) == 0:
            print("[-] No python block found")
            return
        
        python_code = python_codes[0]

        data_dir = get_data_directory()
        log_dir = os.path.join(data_dir, "chatbot", "debug")
        os.makedirs(log_dir, exist_ok=True)
        python_filename = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S.pytmp")
        try:
            with open(os.path.join(log_dir, python_filename), 'w', encoding='utf-8') as f:
                f.write(python_code)
        except Exception as e:
            print(f"[-] Warning: Failed to save debug script: {e}")
        
        # Risk scan (AST)
        risks = _scan_risks(python_code)
        if risks:
            risk_str = ", ".join(risks)

            answer = QtWidgets.QMessageBox.warning(
                getattr(self, "parent", None),
                "Risky Script Detected",
                f"The generated script uses potentially dangerous calls:\n\n"
                f"  {risk_str}\n\n"
                f"This will run inside IDA Pro with your user privileges.\n"
                f"Do you want to continue?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No,
            )

            if answer != QtWidgets.QMessageBox.Yes:
                print(f"[-] Execution cancelled by user (risky calls: {risk_str})")
                return
        
        output_dir = os.path.join(data_dir, "chatbot", "pygen_output")
        os.makedirs(output_dir, exist_ok=True)
        print(f"[+] Output directory set to {output_dir}")
        
        exec_globals = globals().copy()
        exec_globals['__name__']   = '__main__'
        exec_globals['OUTPUT_DIR'] = output_dir
        exec_globals['os'] = _make_safe_os(os, output_dir)

        # Dynamic population of all IDA modules and standard libraries
        exec_globals.update({
            'QtWidgets':    QtWidgets,
            'QtCore':       QtCore,
            'QtGui':        QtGui,
            'sys':          sys,
            'json':         json,
            're':           re,
            'datetime':     datetime,
            'traceback':    traceback,
        })

        # Dynamically add all modules starting with 'ida' to the global namespace
        for mod_name, mod in sys.modules.items():
            if mod_name.startswith('ida') and mod is not None:
                exec_globals[mod_name] = mod

        # ----- running and redirecting output
        print("[+] Executing...")

        errors = ""
        output = ""

        # Use context manager for string buffer to ensure closure and cleanup
        with io.StringIO() as buf:
            old_out, old_err = sys.stdout, sys.stderr
            sys.stdout = sys.stderr = buf
            try:
                # Execute the code in the prepared global environment
                exec(python_code, exec_globals)
            except Exception:
                errors = traceback.format_exc()
            finally:
                # Restore stdout/stderr immediately
                sys.stdout, sys.stderr = old_out, old_err
            
            output = buf.getvalue()

        if output:
            print(output)
        
        prompt = f"[+] Output:\n{output}\n"
        if errors:
            print(f"[-] Execution Errors:\n{errors}")
            prompt += f"[-] Errors:\n{errors}"

        # Add result to context so LLM knows what happened
        LLMContext.add("user", prompt)
        print("[+] Execution finished and added to conversation history.")

        display_text = self.get_text() + f"\n\n{'='*40}\n[Run Output]\n{output}"
        if errors:
            display_text += f"\n[Errors]\n{errors}"
        
        _safe_chat_form_update(self, display_text)

    def on_regen_code(self):
        global _pygen_shutting_down
        _pygen_shutting_down = False # Ensure updates are allowed
        
        additional_comments = self.comment_input.text()
        self.comment_input.clear()
        
        rag_requests = [request.strip() for request in re.findall(r"```request\n([\s\S]*?)\n```", self.get_text())]
        
        if len(rag_requests) > 0:
            for rag_request in rag_requests:
                results = LLMContext.query_rag(rag_request, num_results=3)

                additional_comments += f"\n\n===== RAG responses for: {rag_request} ====="
                for result in results:
                    type_name, description = result
                    additional_comments += f"\n{type_name}: {description}"

        # If it's a pure regeneration (no comments and no RAG fulfilling), 
        # we should pop the last assistant message to avoid "continuation" hallucination.
        if not additional_comments and len(LLMContext.messages) > 0 and LLMContext.messages[-1]["role"] == "assistant":
            LLMContext.messages.pop()

        # Cancel any in-flight query
        if self.current_query:
            self.current_query.is_cancelled = True

        self.current_query = OpenRouterQuery()
        run_in_background(self.current_query.send_next_prompt_async, additional_comments, self)
        print(f"[+] Regenerating...")

    def update_text(self, text):
        _safe_chat_form_update(self, text)

    def get_text(self):
        if _qt_obj_valid(self.text_box):
            return self.text_box.toPlainText()
        return ""

    def OnClose(self, form):
        self.is_closed = True
        # Cancel any in-flight query to allow thread to terminate
        if self.current_query:
            self.current_query.is_cancelled = True
            self.current_query = None
        print("LLMChatForm closed")

class DeobfuscateHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        super().__init__()

    @staticmethod
    def is_iat_address(func_ea):
        global _IAT_SEGMENT_BOUNDS
        if _IAT_SEGMENT_BOUNDS is None:
            seg_start = 0
            seg_end = 0
            for seg_ea in idautils.Segments():
                seg_name = idc.get_segm_name(seg_ea)
                if seg_name == '.idata':
                    seg_start = idc.get_segm_start(seg_ea)
                    seg_end = idc.get_segm_end(seg_ea)
                    break
            _IAT_SEGMENT_BOUNDS = (seg_start, seg_end)

        return _IAT_SEGMENT_BOUNDS[0] <= func_ea <= _IAT_SEGMENT_BOUNDS[1]
    
    @staticmethod
    def get_global_references(func_ea):
        """
        Returns a list of all global addresses referenced within a function.
        Global refs include direct memory or data references, excluding calls/jumps.
        """
        print(f"[DEBUG] get_global_references for {hex(func_ea)}")
        refs = set()
        func = idaapi.get_func(func_ea)
        if not func:
            return []

        # Iterate over all instructions in the function
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if not idc.is_code(idc.get_full_flags(head)):
                continue

            # Check for data references made by this instruction
            for dref in idautils.DataRefsFrom(head):
                # Exclude stack and local addresses (keep only globals)
                if not idaapi.get_func(dref):  
                    refs.add(dref)
        
        print(f"[DEBUG] get_global_references found {len(refs)} refs")
        return sorted(refs)

    @staticmethod
    def get_calls(func_ea):      
        print(f"[DEBUG] get_calls for {hex(func_ea)}")
        func = idaapi.get_func(func_ea)

        if not func:
            return []

        call_addrs = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnemonic = idc.print_insn_mnem(head)
            
            if mnemonic == "call":
                call_target_ea = idc.get_operand_value(head, 0)
                call_addrs.append(call_target_ea)
            
            elif mnemonic == "jmp":
                jmp_target_ea = idc.get_operand_value(head, 0)
                jmp_func = ida_funcs.get_func(jmp_target_ea)
                
                if not jmp_func:
                    continue

                if jmp_func.start_ea == jmp_target_ea:
                    call_addrs.append(jmp_target_ea)
        
        print(f"[DEBUG] get_calls found {len(call_addrs)} calls")
        return call_addrs

    @staticmethod
    def get_call_chain(start_func_ea, is_pe, query_obj=None):
        """
        Iterative DFS to get all reachable functions from a starting address.
        """
        print(f"[DEBUG] get_call_chain starting at {hex(start_func_ea)}")
        processed = []      # The 'Include' list for the LLM
        stack = [start_func_ea]

        loop_count = 0
        while stack:
            loop_count += 1
            if query_obj and query_obj.is_cancelled:
                print("[DEBUG] get_call_chain: cancelled")
                return []
            
            current_ea = stack.pop()
            if current_ea in processed:
                continue
            
            if loop_count % 10 == 0:
                print(f"[DEBUG] get_call_chain: loop {loop_count}, processed={len(processed)}, stack={len(stack)}")

            def is_lib_or_invalid():
                f = ida_funcs.get_func(current_ea)
                return not f or bool(f.flags & ida_funcs.FUNC_LIB)
            
            # Skip library functions
            lib_check_res = ida_kernwin.execute_sync(is_lib_or_invalid, ida_kernwin.MFF_READ)
            if lib_check_res == -1:
                print(f"[DEBUG] get_call_chain: execute_sync (lib_check) failed for {hex(current_ea)}")
                # Continue anyway or handle error? Let's continue for now.
            elif lib_check_res:
                continue

            # 1. Skip Imports/IAT to keep the LLM focused on local logic
            # is_iat_address is safe if called with an address because _IAT_SEGMENT_BOUNDS 
            # was pre-calculated on the main thread in Phase 0.
            if is_pe and DeobfuscateHandler.is_iat_address(current_ea):
                continue
                
            processed.append(current_ea)
            
            # 2. Get callees
            # Ensure get_calls returns start addresses of functions
            result = {}
            def get_calls_sync(ea=current_ea):
                result['calls'] = DeobfuscateHandler.get_calls(ea)
                return 1

            ida_kernwin.execute_sync(get_calls_sync, ida_kernwin.MFF_READ)
            for call_ea in result.get('calls', []):
                if call_ea not in processed:
                    stack.append(call_ea)
        
        print(f"[DEBUG] get_call_chain finished, found {len(processed)} functions")
        return processed

    @staticmethod
    def get_line_pseudocode(vdui):
        # Check if we have a valid hexrays window
        if not vdui:
            return ""

        # Get the current line number and total lines
        line_num = vdui.cfunc.get_line_item(vdui.cfunc.entry_ea, None)
        
        # This is a hacky way but works to get the current line:
        # Get the line under the cursor
        current_line = vdui.get_current_line()
        if not current_line:
            return ""
            
        # Clean up HTML tags if any (IDA 7.x+ uses them in some views)
        clean_line = ida_kernwin.tag_remove(current_line)
        return clean_line.strip()

    @staticmethod
    def generate_script_and_window(user_prompt: str, target_func_name: str, is_chatbot_tool_call=False):
        global _pygen_shutting_down
        _pygen_shutting_down = False # Ensure updates are allowed
        
        chat_form = get_or_create_chat_form()
        try:
            if is_chatbot_tool_call:
                # Create the form first without showing
                chat_form.Show(LLMChatForm.FORM_NAME)  # show it first
                
                # Then move it to the target tab group
                form_widget = ida_kernwin.find_widget(LLMChatForm.FORM_NAME)
                target_widget = ida_kernwin.find_widget(LLMChatForm.CHATBOT_WINDOW_NAME)
                
                if form_widget and target_widget:
                    ida_kernwin.activate_widget(form_widget, True)
            else:
                chat_form.Show(LLMChatForm.FORM_NAME)

            # Process Qt events to ensure OnCreate runs and widgets are initialized
            app = QtWidgets.QApplication.instance()
            if app:
                # Give OnCreate time to be dispatched on the main thread and initialize widgets
                for _ in range(20): # Up to 1s wait
                    app.processEvents()
                    if chat_form.text_box is not None:
                        break
                    import time; time.sleep(0.05)
                
            if chat_form.text_box is None:
                print(f"[WARN] generate_script_and_window: OnCreate never finished or text_box is still None for {chat_form}")

            # --- START OF BACKGROUND FLOW ---
            query_obj = OpenRouterQuery()
            chat_form.current_query = query_obj # Allow cancellation
            
            # The gathering logic is now inside send_first_prompt_async
            global _pygen_bg_thread
            _pygen_bg_thread = run_in_background(
                query_obj.send_first_prompt_async,
                user_prompt, target_func_name, chat_form
            )
            print("[DEBUG] generate_script_and_window: Background thread launched.")
            return "Opened Script Generation Window"
        except Exception as e:
            msg = f"Error during script generation setup: {str(e)}"
            print(f"[-] {msg}")
            import traceback
            traceback.print_exc()
            # If we haven't started the async thread yet, we must update the UI here
            _safe_chat_form_update(chat_form, msg)
            return msg

    def activate(self, ctx):
        ea = ctx.cur_ea
        print(f"[DEBUG] ea: {ea}")
        asm_text = idc.GetDisasm(ea).replace('    ', ' ')
        log = f"[+] Selected Instruction: {asm_text}"
        user_prompt = f"{log}\n"

        print(f"[DEBUG] asm_text: {asm_text}, {not (asm_text.startswith('call') or asm_text.startswith('j'))}")

        # not a call or jump, send the current function instead of the function referenced in the instruction
        if not (asm_text.startswith('call') or asm_text.startswith('j')):
            target_ea = idaapi.get_func(ea).start_ea

        else:        
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            line_pseudocode = DeobfuscateHandler.get_line_pseudocode(vu)
            log = f"[+] Selected Line: {line_pseudocode}"
            user_prompt += f"{log}\n"
            target_ea = idc.get_operand_value(ea, 0)

        target_func = idc.get_func_name(target_ea)
        DeobfuscateHandler.generate_script_and_window(user_prompt, target_func)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

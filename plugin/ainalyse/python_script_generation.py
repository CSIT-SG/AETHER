import idaapi
import ida_kernwin
import idc
import idautils
import ida_funcs
import ida_hexrays
import PyQt5.QtWidgets as QtWidgets
import re
import datetime
import io
import sys
import json
import threading
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import os

from . import load_config
from .async_manager import run_async_in_ida
from .ssl_helper import create_openai_client_with_custom_ca
from .custom_set_cmt import custom_get_pseudocode

RAG_FILE = "IDA9_RAG.json"

class OpenRouterQuery:
    def set_system_prompt(self):
        self.system_prompt = """
You MUST write an ida9 python deobfuscation script that automatically deobfuscates all references to the marked deobfuscation function and nothing else.
```python
# python code here
```

If you need a particular IDApython function, make a RAG request by giving a description of the function like this: 
```request
Function to read bytes at an address
```
Use the "request" block. I will return a list of likely candidates. Do not stop generating python code. sThe python deobfuscation script should be wrapped in a block like so:

Only have 1 python block your response. DO NOT USE the 'if __name__ == "__main__":' check and call main() directly.
Rename variables in pseudocode, and provide the list of changes.
Add comments in pseudocode to display the full deobfuscated string.
Print verbose debugging, comments, renames, and steps to the console via print().
"""

    def __init__(self, model="qwen/qwen3-coder:exacto"):
        self.model = model
        self.set_system_prompt()

    def send(self, messages: list) -> str:
        config = load_config()
        client = create_openai_client_with_custom_ca(
            config["OPENAI_API_KEY"],
            config["OPENAI_BASE_URL"],
            config.get("CUSTOM_CA_CERT_PATH", ""),
            config.get("CLIENT_CERT_PATH", ""),
            config.get("CLIENT_KEY_PATH", ""),
            feature="python_script_generation"
        )

        # FOR DEBUG/HISTORY
        with open('convo.json', 'w') as f:
            json.dump(LLMContext.messages, f, indent=4)

        response = client.chat.completions.create(
            model=config.get("OPENAI_MODEL", "gpt-4"),
            messages=messages,
            max_tokens=config.get("CHATBOT_MAX_TOKENS", 65536),
            temperature=0.7,
        )
        
        # print(f"[DEBUG] response: {response}")

        if hasattr(response, 'error') and len(response.error) > 0:
            print(f"[DEBUG] response.error: {response.error}")
            error_message = response.error['message']
            error_code = response.error['code']
            return f"{error_message}, {error_code}"

        response_text = response.choices[0].message.content.strip()
        LLMContext.add("assistant", response_text)

        # FOR DEBUG/HISTORY
        with open('convo.json', 'w') as f:
            json.dump(LLMContext.messages, f, indent=4)

        return response_text

    def send_first_prompt_async(self, user_prompt, chat_form):
        LLMContext.add("system", self.system_prompt)
        LLMContext.add("user", user_prompt)
        
        response = self.send(LLMContext.messages)
        ida_kernwin.execute_sync(lambda: chat_form.update_text(response), ida_kernwin.MFF_FAST)

    def send_next_prompt_async(self, additional_comments, chat_form):
        if len(additional_comments) > 0:
            LLMContext.add("user", additional_comments)

        response = self.send(LLMContext.messages)
        ida_kernwin.execute_sync(lambda: chat_form.update_text(response), ida_kernwin.MFF_FAST)
        print(f"[+] Regenerated")

class LLMContext:
    messages = []

    def clear():
        LLMContext.messages = []

    def add(role: str, content: str):
        data = {
            "role": role,
            "content": content
        }
        LLMContext.messages.append(data)

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

class LLMChatForm(ida_kernwin.PluginForm):
    FORM_NAME = "AETHER IDAPython Generation"
    CHATBOT_WINDOW_NAME = "AETHER Chatbot"

    def OnCreate(self, form):
        # Called when the form is created
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        layout = QtWidgets.QVBoxLayout()

        # --- Text area (read-only)
        self.text_box = QtWidgets.QPlainTextEdit()
        self.text_box.setReadOnly(True)
        self.text_box.setPlainText("Waiting for LLM response...")
        layout.addWidget(self.text_box)

        # --- Comment input field (for user input)
        comment_layout = QtWidgets.QHBoxLayout()
        comment_label = QtWidgets.QLabel("Additional LLM Prompts:")
        self.comment_input = QtWidgets.QLineEdit()
        self.comment_input.setPlaceholderText("Type additional comments here...")
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
        ida_kernwin.info("Run Code clicked!")
        text = self.get_text()

        python_codes = re.findall(r"```python\n([\s\S]*?)\n```", text)
        if len(python_codes) == 0:
            print("[-] No python block found")
            return
        
        python_code = python_codes[0]

        python_filename = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S.pytmp")
        with open(python_filename, 'w') as f:
            f.write(python_code)
        
        # ----- running and redirecting output
        print("[+] Executing...")

        buf = io.StringIO()
        errors = ""

        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = buf
        try:
            exec(python_code, {})
        except Exception as e:
            errors = str(e)
        finally:
            sys.stdout, sys.stderr = old_out, old_err

        output = buf.getvalue()
        prompt = f"[+] Output: {output}"
        print(output)

        if len(errors) > 0:
            prompt += f"[-] Errors: {errors}"

        LLMContext.add("user", prompt)
        # self.update_text(output)

    def on_regen_code(self):
        additional_comments = self.comment_input.text()
        
        rag_requests = [request.strip() for request in re.findall(r"```request\n([\s\S]*?)\n```", self.get_text())]
        
        if len(rag_requests) > 0:
            for rag_request in rag_requests:
                results = LLMContext.query_rag(rag_request, num_results=3)

                additional_comments += f"\n\n===== RAG responses for: {rag_request} ====="
                for result in results:
                    type_name, description = result
                    additional_comments += f"\n{type_name}: {description}"

        orq = OpenRouterQuery()
        threading.Thread(target=orq.send_next_prompt_async, args=(additional_comments, self)).start()
        print(f"[+] Regenerating...")

    def update_text(self, text):
        self.text_box.setPlainText(text)

    def get_text(self):
        return self.text_box.toPlainText()

    def OnClose(self, form):
        print("LLMChatForm closed")

class DeobfuscateHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        super().__init__()

    @staticmethod
    def is_iat_address(func_ea):
        for seg_ea in idautils.Segments():
            seg_name = idc.get_segm_name(seg_ea)
            if seg_name != '.idata':
                continue

            seg_start = idc.get_segm_start(seg_ea)
            seg_end = idc.get_segm_end(seg_ea)
            break

        return seg_start <= func_ea <= seg_end
    
    @staticmethod
    def get_global_references(func_ea):
        """
        Returns a list of all global addresses referenced within a function.
        Global refs include direct memory or data references, excluding calls/jumps.
        """
        refs = set()
        func = idaapi.get_func(func_ea)
        if not func:
            # print(f"Invalid function address: {hex(func_ea)}")
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
        
        return sorted(refs)

    @staticmethod
    def get_calls(func_ea):      
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
        
        return call_addrs

    @staticmethod
    def get_call_chain(func_ea, processed_func_eas):
        if func_ea in processed_func_eas:
            return
        
        # on windows, check if function is imported from IAT table
        if idaapi.get_file_type_name().startswith("Portable executable") and DeobfuscateHandler.is_iat_address(func_ea):
            return

        processed_func_eas.append(func_ea)
        call_eas = DeobfuscateHandler.get_calls(func_ea)

        for call_ea in call_eas:
            DeobfuscateHandler.get_call_chain(call_ea, processed_func_eas)
        
        return processed_func_eas

    @staticmethod
    def get_line_pseudocode(vu):
        if not vu or not vu.cfunc:
            return None
        
        line_num = vu.cpos.lnnum
        if line_num >= len(vu.cfunc.pseudocode):
            return None
        
        sline = vu.cfunc.pseudocode[line_num]
        line_pseudocode = idaapi.tag_remove(sline.line)
        return line_pseudocode

    @staticmethod
    def generate_script_and_window(prompt, target_func, is_chatbot_tool_call=False):
        LLMContext.clear()
        print(f"[+] Opening new window")

        target_ea = idc.get_name_ea_simple(target_func)
        prompt += f"[+] Marked function {target_func} ({hex(target_ea)}) for script generation\n"
        
        func_eas = DeobfuscateHandler.get_call_chain(target_ea, processed_func_eas=[])
        func_pseudocode_map = {func_ea: custom_get_pseudocode(func_ea) for func_ea in func_eas}

        for func_ea in func_pseudocode_map:
            pseudocode = func_pseudocode_map[func_ea]
            prompt += f"```{hex(func_ea)}\n{pseudocode}\n```\n"

            globals = DeobfuscateHandler.get_global_references(func_ea)
            for ea in globals:
                prompt += f"{hex(ea)}: {idc.get_name(ea)}\n"

        chat_form = LLMChatForm()
        if is_chatbot_tool_call:
            # Create the form first without showing
            chat_form.Show(LLMChatForm.FORM_NAME)  # show it first
            
            # Then move it to the target tab group
            form_widget = ida_kernwin.find_widget(LLMChatForm.FORM_NAME)
            target_widget = ida_kernwin.find_widget(LLMChatForm.CHATBOT_WINDOW_NAME)
            
            # print(f"[DEBUG] form_widget: {form_widget}")
            # print(f"[DEBUG] target_widget: {target_widget}")
            
            if form_widget and target_widget:
                ida_kernwin.activate_widget(form_widget, True)
        else:
            chat_form.Show(LLMChatForm.FORM_NAME)

        orq = OpenRouterQuery()
        threading.Thread(
            target=orq.send_first_prompt_async,
            args=(prompt, chat_form),
            daemon=True
        ).start()

    def activate(self, ctx):
        ea = ctx.cur_ea
        # print(f"[DEBUG] ea: {ea}")
        asm_text = idc.GetDisasm(ea).replace('    ', ' ')
        log = f"[+] Selected Instruction: {asm_text}"
        user_prompt = f"{log}\n"

        # print(f"[DEBUG] asm_text: {asm_text}, {not (asm_text.startswith('call') or asm_text.startswith('j'))}")

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
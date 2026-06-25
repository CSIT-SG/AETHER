import json
import os
import re
from ainalyse.ssl_helper import create_openai_client_with_custom_ca
from . import finalize_prompt


def _extract_json_object(text):
    """Best-effort extraction of a JSON object from model output text."""
    if not isinstance(text, str):
        return None

    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if len(lines) >= 2:
            cleaned = "\n".join(lines[1:])
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()

    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        snippet = cleaned[start:end + 1]
        try:
            parsed = json.loads(snippet)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None
    return None


def _empty_result() -> dict:
    """Return a fresh, empty analysis result dict."""
    return {
        "function_name": None,
        "summary": None,
        "variable_renames": {},
        "function_renames": {},
        "comments": {},
    }


def _result_has_content(r: dict) -> bool:
    return any([
        r.get("function_name"),
        r.get("summary"),
        r.get("variable_renames"),
        r.get("function_renames"),
        r.get("comments"),
    ])


def _parse_structured_output(text: str) -> dict | None:
    """Parse tool-call style blocks into a result dict."""
    if not isinstance(text, str) or not text.strip():
        return None

    result = _empty_result()

    blocks = []
    cleaned = text.strip()
    if "```" in cleaned:
        blocks = re.findall(r"```(.*?)```", cleaned, re.DOTALL)
    else:
        return None

    for block in blocks:
        if not block:
            continue
        lines = block.splitlines()
        if not lines:
            continue
        header = lines[0].strip().lower()
        body_lines = [line.rstrip() for line in lines[1:]]
        body = "\n".join(body_lines).strip()

        if header == "function_name":
            for line in body_lines:
                candidate = line.strip()
                if candidate:
                    result["function_name"] = candidate
                    break
        elif header == "summary":
            result["summary"] = body if body else None
        elif header == "rename_local_variable":
            for line in body_lines:
                line = line.strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split("|", 1)]
                if len(parts) == 2 and parts[0] and parts[1]:
                    result["variable_renames"][parts[0]] = parts[1]
        elif header == "rename_function":
            for line in body_lines:
                line = line.strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split("|", 1)]
                if len(parts) == 2 and parts[0] and parts[1]:
                    result["function_renames"][parts[0]] = parts[1]
        elif header == "set_comment":
            for line in body_lines:
                line = line.strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split("|", 1)]
                if len(parts) == 2 and parts[0] and parts[1]:
                    result["comments"][parts[0]] = parts[1]

    return result if _result_has_content(result) else None


def _parse_tool_calls(message) -> dict | None:
    """Parse native tool calls into a result dict."""
    tool_calls = getattr(message, "tool_calls", None)
    if not tool_calls:
        return None

    result = _empty_result()

    for call in tool_calls:
        func = getattr(call, "function", None)
        if func is None:
            continue
        name = getattr(func, "name", "")
        args_raw = getattr(func, "arguments", None)
        if not name:
            continue

        args = None
        if isinstance(args_raw, str):
            try:
                args = json.loads(args_raw)
            except Exception:
                args = None
        elif isinstance(args_raw, dict):
            args = args_raw

        if not isinstance(args, dict):
            continue

        if name == "set_function_name":
            value = args.get("name")
            if isinstance(value, str) and value.strip():
                result["function_name"] = value.strip()
        elif name == "set_summary":
            value = args.get("summary")
            if isinstance(value, str) and value.strip():
                result["summary"] = value.strip()
        elif name == "rename_local_variable":
            old_name = args.get("old_name")
            new_name = args.get("new_name")
            if isinstance(old_name, str) and isinstance(new_name, str) and old_name and new_name:
                result["variable_renames"][old_name] = new_name
        elif name == "rename_function":
            old_name = args.get("old_name")
            new_name = args.get("new_name")
            if isinstance(old_name, str) and isinstance(new_name, str) and old_name and new_name:
                result["function_renames"][old_name] = new_name
        elif name == "set_comment":
            address = args.get("address")
            comment = args.get("comment")
            if isinstance(address, str) and isinstance(comment, str) and address and comment:
                result["comments"][address] = comment

    return result if _result_has_content(result) else None


class LLMClient:
    def __init__(self, config):
        self.config = config
        self.api_key = config.get("OPENAI_API_KEY", "")
        self.model = config.get("OPENAI_MODEL", "") 
        self.gatherer_model = config.get("GATHERER_MODEL") or self.model
        self.base_url = config.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        
        # SSL and Certs
        self.custom_ca_cert_path = config.get("CUSTOM_CA_CERT_PATH", "")
        self.client_cert_path = config.get("CLIENT_CERT_PATH", "")
        self.client_key_path = config.get("CLIENT_KEY_PATH", "")
        self.extra_body = config.get("OPENAI_EXTRA_BODY", {})
        timeout_raw = config.get("OPENAI_TIMEOUT_SECONDS", 90)
        try:
            self.timeout_seconds = max(1, int(timeout_raw or 90))
        except Exception:
            self.timeout_seconds = 90
        self._system_prompt = self._load_system_prompt()
        self._shared_client = None

    def __enter__(self):
        self._shared_client = self._create_client()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if self._shared_client:
            try:
                # httpx client close
                if hasattr(self._shared_client, "_http_client") and self._shared_client._http_client:
                    self._shared_client._http_client.close()
            except Exception:
                pass
            self._shared_client = None

    def _create_client(self):
        """Create an OpenAI compatible client identically to annotator.py/gatherer.py"""
        try:
            return create_openai_client_with_custom_ca(
                self.api_key, 
                self.base_url, 
                self.custom_ca_cert_path, 
                self.client_cert_path, 
                self.client_key_path, 
                "annotation"
            )
        except Exception as e:
            print(f"[AETHER] [FullAnalysis] Failed to create LLM client: {e}")
            return None

    def _get_client(self):
        """Returns the shared client or creates a transient one if none exists."""
        if self._shared_client:
            return self._shared_client
        return self._create_client()

    def _load_system_prompt(self):
        try:
            prompt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts", "fanalysis-prompt.txt")
            with open(prompt_path, "r", encoding="utf-8") as f:
                system_content = f.read()
            return finalize_prompt(system_content, self.config)
        except Exception as e:
            print(f"[AETHER] [FullAnalysis] Error reading prompt file: {e}")
            return (
                "You are a skilled reverse engineer operating in IDA Pro, assisting the human user. "
                "Produce ONLY tool-call blocks."
            )

    def analyze_function(self, prompt):
        """
        Sends the binary analysis prompt to the LLM backend.
        Returns JSON structure mapping:
        {
          "function_name": "...", 
          "variable_renames": {"old": "new"}, 
          "summary": "..."
        }
        """
        if not self.api_key:
            print("[AETHER] [FullAnalysis] Warning: No API key provided for LLMClient.")
            return None, None

        if not self.model:
            print("[AETHER] [FullAnalysis] Warning: No model configured for LLMClient.")
            return None, None
        else:
            print(f"[AETHER] [FullAnalysis] Using model '{self.model}' for analysis.")

        system_content = self._system_prompt

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "set_function_name",
                    "description": "Set the descriptive name for the analyzed function.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"}
                        },
                        "required": ["name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "set_summary",
                    "description": "Provide a summary of the function's behavior.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "summary": {"type": "string"}
                        },
                        "required": ["summary"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "rename_local_variable",
                    "description": "Rename a local variable from a default placeholder to a descriptive name.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "old_name": {"type": "string"},
                            "new_name": {"type": "string"},
                        },
                        "required": ["old_name", "new_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "rename_function",
                    "description": "Rename a callee function with a descriptive name.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "old_name": {"type": "string"},
                            "new_name": {"type": "string"},
                        },
                        "required": ["old_name", "new_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "set_comment",
                    "description": "Attach a comment to an address in the pseudocode.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "address": {"type": "string"},
                            "comment": {"type": "string"},
                        },
                        "required": ["address", "comment"],
                    },
                },
            },
        ]

        try:
            client = self._get_client()
            if not client:
                return None, None

            request_params = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": prompt}
                ],
                "timeout": self.timeout_seconds,
                "tools": tools,
                "tool_choice": "required",
            }
            
            if self.extra_body:
                request_params["extra_body"] = self.extra_body
            
            max_tokens = self.config.get("ANALYSIS_MAX_TOKENS")
            if max_tokens:
                request_params["max_tokens"] = max_tokens

            response = client.chat.completions.create(**request_params)
            
            # Handle empty or missing responses safely
            if not response.choices or not response.choices[0].message:
                print("[AETHER] [FullAnalysis] Warning: LLM returned empty content.")
                return None, getattr(response, "usage", None)

            message = response.choices[0].message
            parsed = _parse_tool_calls(message)

            result_text = getattr(message, "content", "") or ""
            result_text = result_text.strip()

            if not parsed:
                if result_text:
                    parsed = _parse_structured_output(result_text)
                    if not parsed:
                        parsed = _extract_json_object(result_text)

            if not parsed:
                if result_text:
                    # Debug: Show what we are falling back to
                    print(f"[AETHER] [FullAnalysis] [DEBUG] No tool calls found. Falling back to raw text (first 200 chars): {result_text[:200]}...")
                    parsed = {
                        "function_name": None,
                        "summary": result_text,
                        "variable_renames": {},
                        "function_renames": {},
                        "comments": {}
                    }
                else:
                    print("[AETHER] [FullAnalysis] Parse Error. LLM returned empty or malformed structured output.")
                    return None, getattr(response, "usage", None)

            if not parsed.get("summary"):
                # Fallback: if there is plain text content, maybe that's the summary?
                if result_text and len(result_text) > 20:
                    parsed["summary"] = result_text
                    print("[AETHER] [FullAnalysis] Note: Using LLM text content as function summary.")
                else:
                    parsed["summary"] = "No summary provided by model."

            if "function_renames" not in parsed:
                parsed["function_renames"] = {}
            if "variable_renames" not in parsed or not isinstance(parsed.get("variable_renames"), dict):
                parsed["variable_renames"] = {}
            if "comments" not in parsed or not isinstance(parsed.get("comments"), dict):
                parsed["comments"] = {}

            return parsed, getattr(response, "usage", None)
            
        except Exception as e:
            err_msg = str(e)
            if "api_key" in err_msg.lower() or "authentication" in err_msg.lower() or "401" in err_msg:
                print(f"[AETHER] [FullAnalysis] FATAL: Invalid API Key or Authentication Error: {e}")
            elif "rate_limit" in err_msg.lower() or "429" in err_msg:
                print(f"[AETHER] [FullAnalysis] ERROR: Rate limit exceeded: {e}")
            elif "insufficient_quota" in err_msg.lower():
                print(f"[AETHER] [FullAnalysis] FATAL: API Quota exceeded/Insufficient funds: {e}")
            else:
                print(f"[AETHER] [FullAnalysis] LLM Request Error: {e}")
            return None, None

    def analyze_function_chunked(
            self,
            func_name: str,
            code_chunks: list[str],
            child_summaries_str: str,
            idx_info_str: str,
        ):
            """
            Multi-pass analysis for functions that exceed the context limit even
            after all in-place reductions.
    
            Phase 1 — Observation passes (one per chunk):
                Ask the model for concise plain-text observations about each chunk:
                variable purposes, called-function roles, notable patterns.  These
                passes use a lightweight system prompt and request NO tool calls so
                they stay cheap and fast.
    
            Phase 2 — Synthesis pass:
                Combine all observations with the function signature chunk and run
                the normal structured-output analysis.  By this point the model has
                enough context to produce high-quality renames and comments even
                though it never saw the whole function at once.
    
            Returns ``(parsed_result, combined_usage)`` in the same format as
            ``analyze_function``.
            """
            if not self.api_key or not self.gatherer_model:
                return None, None
    
            if not code_chunks:
                return None, None
    
            # ------------------------------------------------------------------
            # Phase 1: one observation pass per chunk
            # ------------------------------------------------------------------
            observation_system = (
                "You are a skilled reverse engineer. You will receive one chunk of a large "
                "decompiled C function. Your task is to produce a concise bullet-point list of "
                "observations: the apparent purpose of local variables, the role of called "
                "functions, and any notable control-flow patterns. "
                "Be brief and factual. Do NOT call any tools. Plain text only."
            )
    
            all_observations: list[str] = []
            total_usage_prompt = 0
            total_usage_completion = 0
            n = len(code_chunks)
    
            client = self._get_client()
            if not client:
                print(f"[AETHER] [FullAnalysis] Chunked analysis: failed to obtain client.")
                return None, None
    
            for i, chunk in enumerate(code_chunks):
                chunk_prompt = (
                    f"Function name: {func_name}\n"
                    f"Chunk {i + 1} of {n}:\n"
                    f"```c\n{chunk}\n```\n"
                    "List your observations:"
                )
                try:
                    obs_request_params = {
                        "model": self.gatherer_model,
                        "messages": [
                            {"role": "system", "content": observation_system},
                            {"role": "user", "content": chunk_prompt},
                        ],
                        "timeout": self.timeout_seconds,
                    }
                    if self.extra_body:
                        obs_request_params["extra_body"] = self.extra_body
                    
                    max_tokens = self.config.get("ANALYSIS_MAX_TOKENS")
                    if max_tokens:
                        obs_request_params["max_tokens"] = max_tokens
                    
                    obs_response = client.chat.completions.create(**obs_request_params)
                    if obs_response.choices and obs_response.choices[0].message:
                        obs_text = obs_response.choices[0].message.content or ""
                        all_observations.append(f"[Chunk {i + 1}/{n}]\n{obs_text.strip()}")
                    if obs_response.usage:
                        total_usage_prompt += getattr(obs_response.usage, "prompt_tokens", 0)
                        total_usage_completion += getattr(obs_response.usage, "completion_tokens", 0)
                except Exception as e:
                    print(f"[AETHER] [FullAnalysis] Chunked analysis: observation pass {i + 1} failed: {e}")
                    # Continue — partial observations are better than none.
    
            # ------------------------------------------------------------------
            # Phase 2: synthesis pass using observations + first chunk (signature)
            # ------------------------------------------------------------------
            observations_block = "\n\n".join(all_observations) if all_observations else "(no observations gathered)"
    
            synthesis_prompt = (
                f"Analyze the following C pseudocode function.\n"
                f"NOTE: This function was too large for the context window. "
                f"Below are observations gathered from {n} code chunks, followed by the "
                f"function signature/opening chunk for reference.\n\n"
                f"### Chunk Observations\n{observations_block}\n\n"
            )
            if idx_info_str:
                synthesis_prompt += f"{idx_info_str}\n"
            if child_summaries_str:
                synthesis_prompt += f"{child_summaries_str}\n"
            synthesis_prompt += (
                f"### Function '{func_name}' (signature / first chunk)\n"
                f"```c\n{code_chunks[0]}\n```\n\n---\n"
            )
    
            result, usage = self.analyze_function(synthesis_prompt)
    
            # Accumulate usage from all phases.
            class _CombinedUsage:
                prompt_tokens = total_usage_prompt + (getattr(usage, "prompt_tokens", 0) if usage else 0)
                completion_tokens = total_usage_completion + (getattr(usage, "completion_tokens", 0) if usage else 0)
    
            return result, _CombinedUsage()

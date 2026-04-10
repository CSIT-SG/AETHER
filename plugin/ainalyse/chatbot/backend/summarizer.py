import os
import asyncio
import time

from ... import load_config
from ...ssl_helper import create_openai_client_with_custom_ca
from .core import AgentState
from .parser import parse_tool_calls

SUMMARIZER_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "..", "prompts", "summarizer_prompt.txt")

class SummarizerAgent:
    def __init__(self):
        self.prompt_template = self._load_prompt()

    def _load_prompt(self) -> str:
        from .tools import ToolNames, TaskStatus
        try:
            with open(SUMMARIZER_PROMPT_PATH, "r", encoding="utf-8") as f:
                f_string_code = 'f"""' + f.read() + '"""'
                safe_globals = {
                    'ToolNames': ToolNames,
                    'TaskStatus': TaskStatus
                }
                return eval(f_string_code, safe_globals, {})
        except Exception as e:
            print(f"[SummarizerAgent] Error loading summarizer prompt: {e}")
            return "You are a summarization agent. Your task is to compress the following conversation history into a concise summary. The summary should retain the key information and the context of the conversation. Do not lose any important information.\n\nConversation History:\n{history}\n\nSummary:"

    def _llm_call(self, history):
        """
        Perform summarizer completion call with retry/backoff.

        Returns:
            Raw OpenAI response object.

        Raises:
            RuntimeError: When all retry attempts are exhausted.
        """
        config = load_config()
        feature = "chatbot"
        client = create_openai_client_with_custom_ca(
            config["OPENAI_API_KEY"],
            config["OPENAI_BASE_URL"],
            config.get("CUSTOM_CA_CERT_PATH", ""),
            config.get("CLIENT_CERT_PATH", ""),
            config.get("CLIENT_KEY_PATH", ""),
            feature
        )

        messages = [{"role": "system", "content": self.prompt_template}] + history

        retry_count = max(0, int(config.get("CHATBOT_REQUEST_RETRIES", 2)))
        retry_delay_sec = float(config.get("CHATBOT_REQUEST_RETRY_DELAY_SEC", 1.5))
        attempts = retry_count + 1
        last_error = None

        for attempt in range(1, attempts + 1):
            try:
                response = client.chat.completions.create(
                    model=config.get("OPENAI_MODEL", "gpt-4"),
                    messages=messages,
                    max_tokens=config.get("CHATBOT_MAX_TOKENS", 4096) // 2,
                    temperature=0.5
                )
                return response
            except Exception as e:
                last_error = e
                if attempt < attempts:
                    wait_seconds = retry_delay_sec * attempt
                    print(
                        f"[SummarizerAgent] LLM request failed "
                        f"(attempt {attempt}/{attempts}): {e}. Retrying in {wait_seconds:.1f}s..."
                    )
                    time.sleep(wait_seconds)

        base_url = config.get("OPENAI_BASE_URL", "<unset>")
        raise RuntimeError(
            f"Summarizer request failed after {attempts} attempts. "
            f"Base URL: {base_url}. Last error: {last_error}"
        )

    async def summarize(self, state: AgentState, finalize: bool = False) -> str:
        """
        Summarizes the conversation history.
        """
        from .tools import TOOL_REGISTRY, ToolNames, save_summary
        if not self.prompt_template:
            return "Error: Summarizer prompt not loaded."
        history = list(state.conversation_history)
        
        history.append({
        "role": "user", 
        "content": "Please generate the summary now based on the system instructions."
        })

        try:
            response = await asyncio.to_thread(self._llm_call, history)

            if not response or not hasattr(response, 'choices') or len(response.choices) == 0:
                error_msg = "LLM returned an empty response (no choices)."
                print(f"[SummarizerAgent] {error_msg}")
                return f"Error: {error_msg}"

            choice = response.choices[0]
            
            if not choice.message or choice.message.content is None:
                error_msg = f"LLM choice exists but content is empty. Finish reason: {getattr(choice, 'finish_reason', 'unknown')}"
                print(f"[SummarizerAgent] {error_msg}")
                return f"Error: {error_msg}"

            response_text = choice.message.content.strip()

            ALLOWED_SUMMARY_TOOLS = [
                ToolNames.ADD_SHORT_TERM_MEMORY
            ]
            tool_calls = parse_tool_calls(response_text)
            tool_outputs = []
            if tool_calls:
                for call in tool_calls:
                    tool_name = call.get("tool_name")
                    args = call.get("args", [])
                    # Limit tool_name to save short term memory
                    if tool_name in TOOL_REGISTRY and tool_name in ALLOWED_SUMMARY_TOOLS:
                        tool_func = TOOL_REGISTRY[tool_name]
                        try:
                            tool_output = tool_func(state, *args)
                            tool_outputs.append(tool_output)
                        except Exception as e:
                            tool_outputs.append(f"Error executing tool '{tool_name}': {e}")
                    else:
                        tool_outputs.append(f"Unknown tool: '{tool_name}'")
                
            save_summary(state, response_text)
            if finalize:
                return response_text
            if tool_calls:
                return "\n".join(tool_outputs)
            return "No output"

        except Exception as e:
            error_message = f"An error occurred during summarization: {e}"
            print(f"[SummarizerAgent] {error_message}")
            return f"Error: Could not summarize history. {e}"
    
async def summarize_conversation(state: AgentState, finalize: bool = False) -> str:
    """Summarizes the conversation history."""
    if len(state.conversation_history) < 2:
        return "Not enough history to summarize."
    from .summarizer import SummarizerAgent
    summarizer = SummarizerAgent()
    summary = await summarizer.summarize(state, finalize)

    if finalize:
        print(summary)
        return summary

    return "Conversation history summarized."

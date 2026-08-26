from uuid import uuid4

from agents import Agent, Runner, SQLiteSession, TResponseInputItem

from aether_utils.logger import get_logger

MAX_SUMMARIZE_CALLS = 2

RETRY_NOTE = (
    "Your previous attempt failed with the error below. You have no tools available, "
    "so reply with the summary text only.\n"
)


def _has_orphan_tool_result(items: list[TResponseInputItem]) -> bool:
    calls = {i.get("call_id") for i in items if i.get("type") == "function_call"}
    return any(
        i.get("type") == "function_call_output" and i.get("call_id") not in calls for i in items
    )


class CompactingSession(SQLiteSession):
    def __init__(
        self,
        session_id: str | None = None,
        db_path: str = ":memory:",
        *,
        summarizer: Agent,
        threshold: int = 10,
        keep_last_n: int = 5,
    ) -> None:
        super().__init__(session_id or str(uuid4()), db_path)

        self._summarizer = summarizer
        self._threshold = threshold
        self._keep_last_n = keep_last_n
        self.logger = get_logger(f"compacting_session-{self.session_id}")

    async def add_items(self, items: list[TResponseInputItem]) -> None:
        await super().add_items(items)

        history = await super().get_items()
        if len(history) <= self._threshold:
            return

        split = len(history) - self._keep_last_n
        while split > 0 and _has_orphan_tool_result(history[split:]):
            split -= 1

        head, tail = history[:split], history[split:]

        compacted_item = await self._compact_history(head)
        if compacted_item is None:
            return

        await super().clear_session()
        await super().add_items([compacted_item, *tail])

    async def _compact_history(
        self, history: list[TResponseInputItem]
    ) -> TResponseInputItem | None:
        self.logger.info(f"Compacting history of {len(history)} items.")

        attempt, result = history, None
        for call in range(MAX_SUMMARIZE_CALLS):
            try:
                result = await Runner.run(self._summarizer, input=attempt, max_turns=1)
                break
            except Exception as error:
                self.logger.warning(f"Compaction failed ({error}).")
                if call + 1 < MAX_SUMMARIZE_CALLS:
                    attempt = [*history, {"role": "user", "content": f"{RETRY_NOTE}{error}"}]

        if result is None:
            self.logger.warning("Compaction kept failing; leaving history uncompacted.")
            return None

        summary = str(result.final_output or "").strip()
        if not summary:
            self.logger.warning("Compaction returned no summary; leaving history uncompacted.")
            return None

        return {
            "role": "system",
            "content": f"Compacted history of {len(history)} items:\n{summary}",
        }

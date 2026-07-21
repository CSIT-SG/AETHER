from agents import Agent, Runner, SQLiteSession, TResponseInputItem


class CompactingSession(SQLiteSession):
    def __init__(
        self,
        session_id: str,
        db_path: str = ":memory:",
        *,
        summarizer: Agent,
        threshold: int = 10,
        keep_last_n: int = 5,
    ) -> None:
        super().__init__(session_id, db_path)

        self._summarizer = summarizer
        self._threshold = threshold
        self._keep_last_n = keep_last_n

    async def add_items(self, items: list[TResponseInputItem]) -> None:
        await super().add_items(items)

        history = await super().get_items()
        if len(history) <= self._threshold:
            return

        # Keep the last N items and compact the rest
        head = history[: -self._keep_last_n]

        # leave the remainder of the history intact
        tail = history[-self._keep_last_n :]

        compacted_item = await self._compact_history(head)
        await super().clear_session()
        await super().add_items([compacted_item, *tail])

    async def _compact_history(self, history: list[TResponseInputItem]) -> TResponseInputItem:
        result = await Runner.run(
            self._summarizer,
            input=history,
            max_turns=1,
        )

        return {
            "role": "system",
            "content": f"Compacted history of {len(history)} items:\n{result.final_output}",
        }

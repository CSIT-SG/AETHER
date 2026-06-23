import json
import os
import re
import threading
import time
from typing import Any

from ainalyse.qt_shim import QtWidgets
QApplication = QtWidgets.QApplication

from ainalyse import load_config
from ainalyse.indexing import FunctionIndexManager
from ainalyse.indexing.function_tagger import DEFAULT_FUNCTION_TAGS
from ainalyse.ssl_helper import create_openai_client_with_custom_ca


class IndexAgent:
    """
    Scout agent that narrows the function index and produces a briefing packet.
    """

    def __init__(self):
        self.config = load_config()
        self.client = create_openai_client_with_custom_ca(
            self.config["OPENAI_API_KEY"],
            self.config["OPENAI_BASE_URL"],
            self.config.get("CUSTOM_CA_CERT_PATH", ""),
            self.config.get("CLIENT_CERT_PATH", ""),
            self.config.get("CLIENT_KEY_PATH", ""),
        )
        self.model = self.config.get("INDEX_AGENT_MODEL") or self.config.get("OPENAI_MODEL", "qwen/qwen3-coder")

        prompt_path = os.path.join(os.path.dirname(__file__), "..", "prompts", "index_agent_prompt.txt")
        with open(prompt_path, "r", encoding="utf-8") as handle:
            self.briefing_prompt = handle.read()

    def search_index(self, user_query: str) -> str:
        idx = FunctionIndexManager.get_index()
        if not idx.is_usable_for_queries():
            return "Error: No usable function index exists. Please run 'Index Binary' first."

        result_container = []
        timing_data: dict[str, float] = {}
        stats: dict[str, int] = {}
        request_start = time.perf_counter()

        def work():
            try:
                result_container.append(self._do_search_index(idx, user_query, timing_data, stats))
            except Exception as exc:
                import traceback

                print(f"[IndexAgent] Error during search: {traceback.format_exc()}")
                result_container.append(f"Error: {exc}")

        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        while thread.is_alive():
            QApplication.processEvents()
            thread.join(0.05)

        total_ms = (time.perf_counter() - request_start) * 1000.0
        print(
            "[IndexAgent][Timing] "
            f"model={self.model} "
            f"total_ms={total_ms:.2f} "
            f"extract_filters_ms={timing_data.get('extract_filters_ms', 0.0):.2f} "
            f"coarse_scoring_ms={timing_data.get('coarse_scoring_ms', 0.0):.2f} "
            f"candidate_pack_ms={timing_data.get('candidate_pack_ms', 0.0):.2f} "
            f"generate_briefing_ms={timing_data.get('generate_briefing_ms', 0.0):.2f} "
            f"format_expand_ms={timing_data.get('format_expand_ms', 0.0):.2f} "
            f"entries_scanned={stats.get('entries_scanned', 0)} "
            f"scored_candidates={stats.get('scored_candidates', 0)} "
            f"top_candidates={stats.get('top_candidates', 0)} "
            f"candidate_chars={stats.get('candidate_chars', 0)}"
        )
        return result_container[0]

    def _do_search_index(self, idx: Any, user_query: str, timing_data: dict[str, float], stats: dict[str, int]) -> str:
        t0 = time.perf_counter()
        filter_data = self._extract_filters(user_query)
        timing_data["extract_filters_ms"] = (time.perf_counter() - t0) * 1000.0

        target_tags = [tag.lower() for tag in filter_data.get("target_tags", [])]
        keywords = [keyword.lower() for keyword in filter_data.get("keywords", [])]

        t1 = time.perf_counter()
        candidate_pool = []
        all_entries = list(idx.entries_by_address.values())
        stats["entries_scanned"] = len(all_entries)
        for entry in all_entries:
            score = 0
            entry_tags_lower = [tag.lower() for tag in entry.tags]

            for tag in target_tags:
                if tag in entry_tags_lower:
                    score += 5

            searchable_high = (entry.summary + " " + entry.name).lower()
            searchable_low = (
                " ".join(entry.key_operations) + " " + " ".join(entry.called_apis) + " " + " ".join(entry.key_constants)
            ).lower()
            for keyword in keywords:
                if keyword in searchable_high:
                    score += 3
                if keyword in searchable_low:
                    score += 1

            if score > 0:
                candidate_pool.append((score, entry))
        timing_data["coarse_scoring_ms"] = (time.perf_counter() - t1) * 1000.0
        stats["scored_candidates"] = len(candidate_pool)

        t2 = time.perf_counter()
        candidate_pool.sort(key=lambda item: item[0], reverse=True)
        top_candidates = [candidate[1] for candidate in candidate_pool[:100]]
        if not top_candidates:
            top_candidates = idx.get_entries_by_importance("MEDIUM")[:50]
            if not top_candidates:
                top_candidates = list(idx.entries_by_address.values())[:50]

        candidate_lines = ["--- CANDIDATE POOL ---"]
        for candidate in top_candidates:
            candidate_lines.append(f"[{candidate.address}] {candidate.name}")
            candidate_lines.append(f"Tags: {', '.join(candidate.tags)}")
            candidate_lines.append(f"Summary: {candidate.summary}")
            candidate_lines.append("")
        candidate_lines.append("--- END POOL ---")
        candidate_text = "\n".join(candidate_lines)
        timing_data["candidate_pack_ms"] = (time.perf_counter() - t2) * 1000.0
        stats["top_candidates"] = len(top_candidates)
        stats["candidate_chars"] = len(candidate_text)

        t3 = time.perf_counter()
        briefing = self._generate_briefing(user_query, candidate_text)
        timing_data["generate_briefing_ms"] = (time.perf_counter() - t3) * 1000.0

        t4 = time.perf_counter()
        result = self._format_and_expand_briefing(idx, briefing)
        timing_data["format_expand_ms"] = (time.perf_counter() - t4) * 1000.0
        return result

    def _extract_filters(self, query: str) -> dict[str, list]:
        available_tags = ", ".join(DEFAULT_FUNCTION_TAGS.keys())
        system_msg = (
            "You are a reverse engineering Information Retrieval expert. "
            "Given a user query, pick broad target tags and keywords to search a binary's function index.\n"
            f"Available tags: {available_tags}\n"
            "Output strictly JSON: {\"target_tags\": [], \"keywords\": []}"
        )
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": f"Query: {query}"},
                ],
                temperature=0.1,
            )
            text = response.choices[0].message.content.strip()
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                return json.loads(match.group(0))
            return json.loads(text)
        except Exception as exc:
            print(f"[IndexAgent] Filter extraction error: {exc}")
            return {"target_tags": [], "keywords": [word for word in query.split() if len(word) > 3]}

    def _generate_briefing(self, query: str, candidate_text: str) -> dict:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.briefing_prompt},
                    {"role": "user", "content": f"USER QUERY: {query}\n\n{candidate_text}"},
                ],
                temperature=0.3,
            )
            text = response.choices[0].message.content.strip()
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                return json.loads(match.group(0))
            return json.loads(text)
        except Exception as exc:
            print(f"[IndexAgent] Briefing generation error: {exc}")
            return {
                "primary_candidates": [],
                "secondary_candidates": [],
                "alternative_hypotheses": [{"hypothesis": f"Error generating briefing: {exc}", "addresses": []}],
            }

    def _format_and_expand_briefing(self, idx: Any, briefing: dict) -> str:
        lines = ["# Index Agent Briefing Packet\n"]

        def format_candidate(node_info):
            addr = node_info.get("address", "")
            reason = node_info.get("reasoning", "")
            entry = idx.get_entry_by_address(addr)
            result = f"- **{addr}**"
            if entry:
                result += f" (`{entry.name}`)"
            result += f": {reason}"
            if entry:
                result += f"\n  Summary: {entry.summary}"
                if entry.tags:
                    result += f"\n  Tags: {', '.join(entry.tags)}"
                if entry.called_apis:
                    result += f"\n  APIs: {', '.join(entry.called_apis[:10])}"
                if entry.callee_functions:
                    result += f"\n  Callees: {', '.join(entry.callee_functions[:10])}"
            return result

        primary = briefing.get("primary_candidates", [])
        secondary = briefing.get("secondary_candidates", [])
        alternatives = briefing.get("alternative_hypotheses", [])

        lines.append("## Tier 1: Primary Candidates")
        if primary:
            lines.extend(format_candidate(candidate) for candidate in primary)
        else:
            lines.append("- None identified.")

        lines.append("\n## Tier 2: Secondary Candidates")
        if secondary:
            lines.extend(format_candidate(candidate) for candidate in secondary)
        else:
            lines.append("- None identified.")

        lines.append("\n## Tier 3: Alternative Hypotheses")
        if alternatives:
            for alternative in alternatives:
                hypothesis = alternative.get("hypothesis", "No hypothesis provided.")
                addresses = alternative.get("addresses", [])
                lines.append(f"- {hypothesis}")
                if addresses:
                    expanded = []
                    for addr in addresses:
                        entry = idx.get_entry_by_address(addr)
                        if entry:
                            expanded.append(f"{addr} (`{entry.name}`)")
                        else:
                            expanded.append(addr)
                    lines.append(f"  Pivot targets: {', '.join(expanded)}")
        else:
            lines.append("- None identified.")
        return "\n".join(lines)

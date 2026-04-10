import json
import os
import re
import threading
import time
from typing import Dict, Any, List

from PyQt5.QtWidgets import QApplication

from .. import load_config
from ..ssl_helper import create_openai_client_with_custom_ca
from ..indexing import FunctionIndexManager
from ..indexing.function_tagger import DEFAULT_FUNCTION_TAGS

class IndexAgent:
    """
    Agent that acts as a scout/Information Retrieval specialist for the Master Agent.
    It takes a user query, scopes down the function index to candidates,
    gets an LLM-driven confidence-tiered briefing, and expands context.
    """

    def __init__(self):
        self.config = load_config()
        self.client = create_openai_client_with_custom_ca(
            self.config["OPENAI_API_KEY"],
            self.config["OPENAI_BASE_URL"],
            self.config.get("CUSTOM_CA_CERT_PATH", ""),
            self.config.get("CLIENT_CERT_PATH", ""),
            self.config.get("CLIENT_KEY_PATH", "")
        )
        self.model = self.config.get("OPENAI_MODEL", "gpt-4")
        
        prompt_path = os.path.join(os.path.dirname(__file__), "..", "prompts", "index_agent_prompt.txt")
        with open(prompt_path, "r", encoding="utf-8") as f:
            self.briefing_prompt = f.read()

    def search_index(self, user_query: str) -> str:
        idx = FunctionIndexManager.get_index()
        if not idx.is_usable_for_queries():
            return "Error: No usable function index exists. Please run 'Index Binary' first."

        result_container = []
        
        def work():
            try:
                res = self._do_search_index(idx, user_query)
                result_container.append(res)
            except Exception as e:
                import traceback
                print(f"[IndexAgent] Error during search: {traceback.format_exc()}")
                result_container.append(f"Error: {e}")

        # Run heavy logic in a separate thread so we don't block the main event loop
        t = threading.Thread(target=work)
        t.start()
        
        # Manually pump the event loop while waiting to keep the UI from freezing
        while t.is_alive():
            QApplication.processEvents()
            t.join(0.05)
            
        return result_container[0]

    def _do_search_index(self, idx: Any, user_query: str) -> str:
        # Stage 1: Coarse Gathering via fast LLM filter extraction
        filter_data = self._extract_filters(user_query)
        target_tags = [t.lower() for t in filter_data.get("target_tags", [])]
        keywords = [k.lower() for t in filter_data.get("keywords", []) for k in filter_data.get("keywords", [])] # flattened just in case
        keywords = [k.lower() for k in filter_data.get("keywords", [])]

        candidate_pool = []
        # Score functions to gather a wide net (aim for ~50-100 items if possible)
        for ea, entry in idx.entries_by_address.items():
            score = 0
            entry_tags_lower = [t.lower() for t in entry.tags]
            
            # Tag match (+5)
            for t in target_tags:
                if t in entry_tags_lower:
                    score += 5
            
            # Keyword match (+3 for summary/name, +1 for operations/APIs)
            searchable_text_high = (entry.summary + " " + entry.name).lower()
            searchable_text_low = (" ".join(entry.key_operations) + " " + " ".join(entry.called_apis) + " " + " ".join(entry.key_constants)).lower()
            
            for k in keywords:
                if k in searchable_text_high:
                    score += 3
                if k in searchable_text_low:
                    score += 1
                    
            if score > 0:
                candidate_pool.append((score, entry))

        # Sort by score descending and take top 100
        candidate_pool.sort(key=lambda x: x[0], reverse=True)
        top_candidates = [c[1] for c in candidate_pool[:100]]

        if not top_candidates:
            # Fallback if no specific hits: just give top 50 by importance
            top_candidates = idx.get_entries_by_importance("MEDIUM")
            top_candidates = top_candidates[:50]
            if not top_candidates:
                top_candidates = list(idx.entries_by_address.values())[:50]

        # Formatting candidates for the LLM
        candidate_text_lines = ["--- CANDIDATE POOL ---"]
        for c in top_candidates:
            candidate_text_lines.append(f"[{c.address}] {c.name}")
            candidate_text_lines.append(f"Tags: {', '.join(c.tags)}")
            candidate_text_lines.append(f"Summary: {c.summary}")
            candidate_text_lines.append("")
        candidate_text_lines.append("--- END POOL ---")
        candidate_text = "\n".join(candidate_text_lines)

        # Stage 2: Semantic Briefing Packet Generation
        briefing_response = self._generate_briefing(user_query, candidate_text)
        
        # Stage 3 & 4: Parsing and Context Expansion
        return self._format_and_expand_briefing(idx, briefing_response)

    def _extract_filters(self, query: str) -> Dict[str, list]:
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
                    {"role": "user", "content": f"Query: {query}"}
                ],
                temperature=0.1
            )
            text = response.choices[0].message.content.strip()
            # extract json block if needed
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                return json.loads(match.group(0))
            return json.loads(text)
        except Exception as e:
            print(f"[IndexAgent] Filter extraction error: {e}")
            return {"target_tags": [], "keywords": [word for word in query.split() if len(word) > 3]}

    def _generate_briefing(self, query: str, candidate_text: str) -> Dict:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.briefing_prompt},
                    {"role": "user", "content": f"USER QUERY: {query}\n\n{candidate_text}"}
                ],
                temperature=0.3
            )
            text = response.choices[0].message.content.strip()
            
            # extract json block
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                return json.loads(match.group(0))
            return json.loads(text)
        except Exception as e:
            print(f"[IndexAgent] Briefing generation error: {e}")
            return {
                "primary_candidates": [],
                "secondary_candidates": [],
                "alternative_hypotheses": [{"hypothesis": f"Error generating briefing: {str(e)}", "addresses": []}]
            }

    def _format_and_expand_briefing(self, idx: Any, briefing: Dict) -> str:
        lines = ["# Index Agent Briefing Packet\n"]
        
        def format_node(node_info, tier_name):
            addr = node_info.get("address", "")
            reason = node_info.get("reasoning", "")
            entry = idx.get_entry_by_address(addr)
            
            res = f"- **{addr}**"
            if entry:
                res += f" (`{entry.name}`)"
            res += f": {reason}"
            lines.append(res)
            
            # Context Expansion
            if entry and entry.callee_functions:
                callees = entry.callee_functions[:5] # limit expansion
                callee_details = []
                for c_name in callees:
                    c_entry = idx.get_entry_by_name(c_name)
                    if c_entry:
                        importance = c_entry.get_importance_level() or "UNTAGGED"
                        c_tags = ", ".join(c_entry.get_functional_categories())
                        callee_details.append(f"    - `{c_name}` ({c_entry.address}) [{importance}] - Tags: {c_tags}")
                    else:
                        callee_details.append(f"    - `{c_name}` (Not indexed/External)")
                if callee_details:
                    lines.append("  *Highly related callees context:*")
                    lines.extend(callee_details)

        lines.append("## 🥇 Tier 1: Primary Candidates (Core Nodes)")
        primaries = briefing.get("primary_candidates", [])
        if not primaries:
            lines.append("- No primary candidates identified.")
        else:
            for p in primaries:
                format_node(p, "Tier 1")
                
        lines.append("\n## 🥈 Tier 2: Secondary Candidates (Support Nodes)")
        secondaries = briefing.get("secondary_candidates", [])
        if not secondaries:
            lines.append("- No secondary candidates identified.")
        else:
            for s in secondaries:
                format_node(s, "Tier 2")

        lines.append("\n## 🤔 Tier 3: Alternative Hypotheses (Pivot Points)")
        alts = briefing.get("alternative_hypotheses", [])
        if not alts:
            lines.append("- No alternative hypotheses provided.")
        else:
            for a in alts:
                hypo = a.get("hypothesis", "")
                addrs = a.get("addresses", [])
                lines.append(f"- **Hypothesis:** {hypo}")
                for addr in addrs:
                    entry = idx.get_entry_by_address(addr)
                    name_str = f" (`{entry.name}`)" if entry else ""
                    lines.append(f"  - **{addr}**{name_str}")

        lines.append("\n*Note to Master Agent: Do not get stuck on Tier 1 if they seem unrelated upon decompilation. Rapidly pivot to Tier 2 or Alternative Hypotheses.*")
        return "\n".join(lines)

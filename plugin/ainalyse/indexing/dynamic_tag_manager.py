"""
Tracks LLM-generated tags that fall outside the configured taxonomy.

Dynamic tags are hierarchical sub-categories (e.g. ``network:icmp``) or
completely novel categories invented by the LLM at classification time.  They
are persisted inside the ``dynamic_tags`` section of the index JSON so that
resumed runs and downstream consumers can see the full tag vocabulary.
"""

from collections import OrderedDict
from typing import Dict, List, Optional


class DynamicTagManager:
    """Registry for tags created by the LLM that aren't in the configured taxonomy."""

    def __init__(self) -> None:
        self.dynamic_tags: Dict[str, dict] = OrderedDict()

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def register_tag(self, tag_id: str, original_form: str, function_name: str) -> bool:
        """Register *tag_id* as a dynamic tag.

        Returns ``True`` if the tag was **newly** created, ``False`` if it
        already existed (in which case usage count is incremented).
        """
        if tag_id in self.dynamic_tags:
            entry = self.dynamic_tags[tag_id]
            entry["usageCount"] += 1
            examples: List[str] = entry["exampleFunctions"]
            if function_name and function_name not in examples:
                # Keep a bounded list of examples
                if len(examples) < 10:
                    examples.append(function_name)
            return False

        self.dynamic_tags[tag_id] = {
            "originalForm": original_form,
            "description": "",
            "usageCount": 1,
            "exampleFunctions": [function_name] if function_name else [],
        }
        return True

    def is_dynamic(self, tag_id: str) -> bool:
        return tag_id in self.dynamic_tags

    def get_all_dynamic_tags(self) -> Dict[str, dict]:
        return dict(self.dynamic_tags)

    def clear(self) -> None:
        self.dynamic_tags.clear()

    # ------------------------------------------------------------------
    # Persistence helpers (index ↔ manager)
    # ------------------------------------------------------------------

    def initialize_from_index(self, index: object) -> None:
        """Populate this manager from an existing :class:`FunctionIndex`
        (used when resuming an interrupted run)."""
        if hasattr(index, "dynamic_tags") and index.dynamic_tags:
            for tag_id, meta in index.dynamic_tags.items():
                self.dynamic_tags[tag_id] = {
                    "originalForm": meta.get("originalForm", tag_id),
                    "description": meta.get("description", ""),
                    "usageCount": meta.get("usageCount", 0),
                    "exampleFunctions": list(meta.get("exampleFunctions", [])),
                }

    def export_to_index(self, index: object) -> None:
        """Write accumulated dynamic tags back to *index*."""
        if hasattr(index, "dynamic_tags"):
            index.dynamic_tags = OrderedDict(self.dynamic_tags)

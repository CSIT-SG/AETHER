from __future__ import annotations

from abc import ABC, abstractmethod
import json
import os
import re
from typing import Any


class LLMClient(ABC):
    """Protocol for LLM-assisted memory retrieval and organization."""

    @abstractmethod
    def complete(self, prompt: str, **kwargs) -> str:
        raise NotImplementedError

    @abstractmethod
    def evaluate_relevance(self, query: str, content: str) -> float:
        raise NotImplementedError

    @abstractmethod
    def evaluate_relevance_batch(self, query: str, contents: list[str]) -> list[tuple[float, str]]:
        raise NotImplementedError

    @abstractmethod
    def decide_branch_priority(
        self,
        query: str,
        node_name: str,
        node_description: str,
        sample_memories: list[str],
    ) -> tuple[float, str]:
        raise NotImplementedError

    @abstractmethod
    def decide_branch_priority_batch(
        self,
        query: str,
        branches: list[dict[str, Any]],
    ) -> list[tuple[float, str]]:
        raise NotImplementedError

    @abstractmethod
    def analyze_and_categorize(
        self,
        node_name: str,
        node_description: str,
        memories: list[str],
        max_categories: int = 5,
        min_items_per_category: int = 2,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def select_best_node(self, content: str, nodes: list[dict[str, Any]]) -> str:
        raise NotImplementedError


class OpenAILLMClient(LLMClient):
    """OpenAI-compatible LLM client for memory retrieval tasks."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        base_url: str | None = None,
        relevance_threshold: float = 0.3,
        max_tokens: int = 50,
        client: Any = None,
        disable_reasoning: bool = True,
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = base_url or os.environ.get("OPENAI_BASE_URL")
        self.model = model
        self.relevance_threshold = max(0.0, min(relevance_threshold, 1.0))
        self.max_tokens = max_tokens
        self.disable_reasoning = disable_reasoning

        if client is not None:
            self.client = client
            return

        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError("OpenAI SDK not installed. Install with: pip install openai") from exc

        client_kwargs = {"api_key": self.api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        self.client = OpenAI(**client_kwargs)

    def complete(self, prompt: str, max_tokens_override: int | None = None, **kwargs) -> str:
        max_tokens = max_tokens_override or self.max_tokens
        request_kwargs = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a concise memory retrieval assistant. Return only the requested structured output.",
                },
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.1,
            **kwargs,
        }
        if self.disable_reasoning:
            request_kwargs.setdefault("extra_body", {"reasoning": {"enabled": False}})

        try:
            response = self.client.chat.completions.create(**request_kwargs)
        except TypeError:
            request_kwargs.pop("extra_body", None)
            response = self.client.chat.completions.create(**request_kwargs)

        choices = getattr(response, "choices", None) or []
        if not choices:
            return ""
        message = getattr(choices[0], "message", None)
        if message is None:
            return ""
        content = getattr(message, "content", None)
        if content:
            return str(content).strip()
        reasoning = getattr(message, "reasoning", None)
        if reasoning:
            return str(reasoning).strip()
        return ""

    def evaluate_relevance(self, query: str, content: str) -> float:
        response = self.complete(self._create_relevance_prompt(query, content))
        score = self._parse_score(response)
        if score == 0.0 and not response:
            score = self._keyword_relevance_fallback(query, content)
        return score if score >= self.relevance_threshold else 0.0

    def evaluate_relevance_batch(self, query: str, contents: list[str]) -> list[tuple[float, str]]:
        if not contents:
            return []
        response = self.complete(self._create_batch_relevance_prompt(query, contents), max_tokens_override=1000)
        results = self._parse_batch_scored_results(response, len(contents))
        if not results or all(score == 0.0 for score, _ in results):
            results = [(self._keyword_relevance_fallback(query, content), "") for content in contents]
        return [(score if score >= self.relevance_threshold else 0.0, reason) for score, reason in results]

    def decide_branch_priority(
        self,
        query: str,
        node_name: str,
        node_description: str,
        sample_memories: list[str],
    ) -> tuple[float, str]:
        response = self.complete(self._create_branch_priority_prompt(query, node_name, node_description, sample_memories))
        score, reason = self._parse_score_and_reason(response)
        if score == 0.0 and not response:
            return self._branch_priority_keyword_fallback(query, node_name, node_description, sample_memories)
        return score, reason

    def decide_branch_priority_batch(
        self,
        query: str,
        branches: list[dict[str, Any]],
    ) -> list[tuple[float, str]]:
        if not branches:
            return []
        response = self.complete(self._create_batch_branch_priority_prompt(query, branches), max_tokens_override=1500)
        results = self._parse_batch_scored_results(response, len(branches))
        if not results or all(score == 0.0 for score, _ in results):
            return [
                self._branch_priority_keyword_fallback(
                    query=query,
                    node_name=str(branch.get("name", "")),
                    node_description=str(branch.get("description", "")),
                    sample_memories=list(branch.get("samples", [])),
                )
                for branch in branches
            ]
        return results

    def select_best_node(self, content: str, nodes: list[dict[str, Any]]) -> str:
        if not nodes:
            return "root"
        response = self.complete(self._create_node_selection_prompt(content, nodes), max_tokens_override=100)
        for node in nodes:
            node_id = str(node.get("id", ""))
            if node_id and node_id in response:
                return node_id
        if "root" in response.lower():
            return "root"
        return "root"

    def analyze_and_categorize(
        self,
        node_name: str,
        node_description: str,
        memories: list[str],
        max_categories: int = 5,
        min_items_per_category: int = 2,
    ) -> list[dict[str, Any]]:
        response = self.complete(
            self._create_categorization_prompt(
                node_name=node_name,
                node_description=node_description,
                memories=memories,
                max_categories=max_categories,
                min_items_per_category=min_items_per_category,
            ),
            max_tokens_override=3000,
        )
        categories = self._parse_categorization_response(response, memories, min_items_per_category)
        if not categories:
            categories = self._categorize_by_keywords(max_categories, min_items_per_category, memories)
        return categories[:max_categories]

    def set_relevance_threshold(self, threshold: float) -> None:
        self.relevance_threshold = max(0.0, min(threshold, 1.0))

    def _create_relevance_prompt(self, query: str, content: str) -> str:
        return f"""Rate how relevant the content is to the query on a scale from 0.0 to 1.0.

Scoring:
- 0.0-0.3: unrelated
- 0.3-0.5: weakly related
- 0.5-0.7: moderately related
- 0.7-0.9: highly related
- 0.9-1.0: exactly relevant

Return only a number.

Query:
{query}

Content:
{content}

Score:
"""

    def _create_batch_relevance_prompt(self, query: str, contents: list[str]) -> str:
        contents_text = "\n".join(f"{index + 1}. {content}" for index, content in enumerate(contents))
        return f"""Rate relevance of each content item to the query from 0.0 to 1.0.

Query: {query}

Contents:
{contents_text}

Return a JSON array with one object per content item:
[{{"score": 0.9, "reason": "Direct match"}}, {{"score": 0.2, "reason": "Unrelated"}}]
"""

    def _create_branch_priority_prompt(
        self,
        query: str,
        node_name: str,
        node_description: str,
        sample_memories: list[str],
    ) -> str:
        samples = "\n".join(f"- {sample}" for sample in sample_memories[:5]) or "(none)"
        return f"""Rate whether this memory tree branch is worth exploring for the query.

Query: {query}
Branch: {node_name}
Description: {node_description}
Samples:
{samples}

Return JSON: {{"score": 0.8, "reason": "Brief reason"}}
"""

    def _create_batch_branch_priority_prompt(self, query: str, branches: list[dict[str, Any]]) -> str:
        lines = []
        for index, branch in enumerate(branches, start=1):
            samples = ", ".join(str(sample) for sample in branch.get("samples", [])[:3]) or "none"
            lines.append(f"{index}. {branch.get('name', '')}: {branch.get('description', '')} (samples: {samples})")
        return f"""Rate how promising each memory branch is for the query from 0.0 to 1.0.

Query: {query}

Branches:
{chr(10).join(lines)}

Return a JSON array with one object per branch:
[{{"score": 0.8, "reason": "Contains relevant memories"}}, {{"score": 0.1, "reason": "Unrelated"}}]
"""

    def _create_node_selection_prompt(self, content: str, nodes: list[dict[str, Any]]) -> str:
        nodes_text = "\n".join(
            f"{index + 1}. ID: {node.get('id')}, Name: {node.get('name')}, Description: {node.get('description')}"
            for index, node in enumerate(nodes)
        )
        return f"""Select the best node for this memory content.

Content: {content}

Available nodes:
{nodes_text}

Return only the best node ID, or root if none are suitable.
"""

    def _create_categorization_prompt(
        self,
        *,
        node_name: str,
        node_description: str,
        memories: list[str],
        max_categories: int,
        min_items_per_category: int,
    ) -> str:
        memories_text = "\n".join(f"{index + 1}. {memory}" for index, memory in enumerate(memories))
        return f"""Group memories into {max_categories} or fewer categories.
Each category must contain at least {min_items_per_category} memories.

Node: {node_name} - {node_description}

Memories:
{memories_text}

Return JSON:
{{"categories": [{{"name": "Category Name", "description": "What this category contains", "memory_numbers": [1, 2, 3]}}]}}
"""

    def _parse_score(self, response: str) -> float:
        try:
            match = re.search(r"(?:score[:\s]*)?(\d*\.?\d+)", response.lower())
            if match:
                return max(0.0, min(float(match.group(1)), 1.0))
        except (AttributeError, ValueError):
            pass
        return 0.0

    def _parse_score_and_reason(self, response: str) -> tuple[float, str]:
        try:
            match = re.search(r"\{[\s\S]*\}", response)
            if match:
                data = json.loads(match.group())
                if isinstance(data, dict):
                    return max(0.0, min(float(data.get("score", 0.0)), 1.0)), str(data.get("reason", ""))
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
        return self._parse_score(response), ""

    def _parse_batch_scored_results(self, response: str, expected_count: int) -> list[tuple[float, str]]:
        try:
            match = re.search(r"\[[\s\S]*\]", response)
            if match:
                data = json.loads(match.group())
                if isinstance(data, list):
                    results = []
                    for item in data[:expected_count]:
                        if isinstance(item, dict):
                            results.append((max(0.0, min(float(item.get("score", 0.0)), 1.0)), str(item.get("reason", ""))))
                        elif isinstance(item, (int, float)):
                            results.append((max(0.0, min(float(item), 1.0)), ""))
                    if len(results) == expected_count:
                        return results
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        scores = []
        for match in re.finditer(r"(\d+\.?\d*|\.\d+)", response):
            try:
                score = float(match.group(1))
            except ValueError:
                continue
            if 0.0 <= score <= 1.0:
                scores.append(score)
        if len(scores) == expected_count:
            return [(score, "") for score in scores]
        return [(0.0, "")] * expected_count

    def _parse_categorization_response(
        self,
        response: str,
        original_memories: list[str],
        min_items_per_category: int,
    ) -> list[dict[str, Any]]:
        try:
            match = re.search(r"\{[\s\S]*\}", response)
            data = json.loads(match.group() if match else response)
            categories = data.get("categories", [])
        except (AttributeError, json.JSONDecodeError, TypeError):
            return []

        parsed = []
        for category in categories:
            items = []
            for number in category.get("memory_numbers", []):
                if isinstance(number, int) and 1 <= number <= len(original_memories):
                    items.append(original_memories[number - 1])
            if len(items) >= min_items_per_category:
                parsed.append(
                    {
                        "name": category.get("name", "Unnamed"),
                        "description": category.get("description", ""),
                        "items": items,
                    }
                )
        return parsed

    def _keyword_relevance_fallback(self, query: str, content: str) -> float:
        query_terms = {term for term in query.lower().split() if term}
        if not query_terms:
            return 0.0
        content_lower = content.lower()
        matches = sum(1 for term in query_terms if term in content_lower)
        return min(matches / len(query_terms), 1.0)

    def _branch_priority_keyword_fallback(
        self,
        query: str,
        node_name: str,
        node_description: str,
        sample_memories: list[str],
    ) -> tuple[float, str]:
        query_terms = {term for term in query.lower().split() if term}
        if not query_terms:
            return 0.0, "empty query"
        haystack = " ".join([node_name, node_description, *sample_memories]).lower()
        matches = sum(1 for term in query_terms if term in haystack)
        if not matches:
            return 0.0, "no match"
        return min(matches / len(query_terms), 1.0), "keyword fallback"

    def _categorize_by_keywords(
        self,
        max_categories: int,
        min_items_per_category: int,
        memories: list[str],
    ) -> list[dict[str, Any]]:
        keyword_groups = {
            "API/Endpoints": ["api", "endpoint", "route", "request"],
            "Database": ["database", "query", "table", "sql"],
            "Authentication": ["auth", "login", "token", "password"],
            "UI/Frontend": ["component", "view", "ui", "render"],
            "Configuration": ["config", "setting", "env", "yaml", "json"],
        }
        categories = []
        used = set()
        for category_name, keywords in keyword_groups.items():
            if len(categories) >= max_categories:
                break
            matching = [
                memory
                for memory in memories
                if memory not in used and any(keyword in memory.lower() for keyword in keywords)
            ]
            if len(matching) >= min_items_per_category:
                categories.append(
                    {
                        "name": category_name,
                        "description": f"Memories related to {category_name.lower()}",
                        "items": matching,
                    }
                )
                used.update(matching)
        remaining = [memory for memory in memories if memory not in used]
        if len(remaining) >= min_items_per_category and len(categories) < max_categories:
            categories.append({"name": "General", "description": "Miscellaneous memories", "items": remaining})
        return categories


class StrictOpenAILLMClient(OpenAILLMClient):
    def __init__(self, api_key: str | None = None, model: str = "gpt-4o-mini", max_tokens: int = 50, **kwargs):
        super().__init__(api_key=api_key, model=model, relevance_threshold=0.7, max_tokens=max_tokens, **kwargs)


class RelaxedOpenAILLMClient(OpenAILLMClient):
    def __init__(self, api_key: str | None = None, model: str = "gpt-4o-mini", max_tokens: int = 50, **kwargs):
        super().__init__(api_key=api_key, model=model, relevance_threshold=0.3, max_tokens=max_tokens, **kwargs)


MemoryLLMClient = OpenAILLMClient

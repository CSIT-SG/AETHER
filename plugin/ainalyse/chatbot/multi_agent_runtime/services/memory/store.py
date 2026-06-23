from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class MemoryPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


from .vector_engine import VectorEngine

@dataclass
class MemoryItem:
    category: str
    priority: MemoryPriority = MemoryPriority.MEDIUM
    id: str = field(default_factory=lambda: str(uuid4()))
    key: str | None = None
    value: Any = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    tags: list[str] = field(default_factory=list)
    related_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    # Vector fields
    vector: npt.NDArray[np.float32] | None = field(default=None, repr=False)
    quantized_codes: npt.NDArray[np.uint8] | None = field(default=None, repr=False)
    quantized_signs: npt.NDArray[np.uint8] | None = field(default=None, repr=False)

    def get_display_content(self) -> str:
        if self.key is not None:
            return f"{self.key}={self.value}"
        return str(self.value) if self.value is not None else ""

    def update(
        self,
        *,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        key: str | None = None,
        value: Any = None,
    ) -> None:
        if key is not None:
            self.key = key
        if value is not None:
            self.value = value
        if tags is not None:
            self.tags = list(tags)
        if metadata is not None:
            self.metadata.update(metadata)
        
        # If content changed, vector needs to be invalidated/recomputed
        if key is not None or value is not None:
            self.vector = None
            self.quantized_codes = None
            self.quantized_signs = None
            
        self.updated_at = datetime.now()

    def add_relation(self, memory_id: str) -> None:
        if memory_id not in self.related_ids:
            self.related_ids.append(memory_id)
            self.updated_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "value": self.value,
            "category": self.category,
            "priority": self.priority.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "tags": list(self.tags),
            "related_ids": list(self.related_ids),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemoryItem":
        return cls(
            id=data["id"],
            key=data.get("key"),
            value=data.get("value"),
            category=data["category"],
            priority=MemoryPriority(data["priority"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            tags=list(data.get("tags", [])),
            related_ids=list(data.get("related_ids", [])),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class MemoryNode:
    name: str
    id: str = field(default_factory=lambda: str(uuid4()))
    description: str = ""
    children: list["MemoryNode"] = field(default_factory=list)
    memory_ids: list[str] = field(default_factory=list)
    parent_id: str | None = None

    def needs_reorganization(self, default_threshold: int) -> bool:
        return len(self.memory_ids) > default_threshold

    def add_child(self, name: str, description: str = "") -> "MemoryNode":
        child = MemoryNode(name=name, description=description, parent_id=self.id)
        self.children.append(child)
        return child

    def add_memory(self, memory_id: str) -> None:
        if memory_id not in self.memory_ids:
            self.memory_ids.append(memory_id)

    def find_node(self, node_id: str) -> "MemoryNode | None":
        if self.id == node_id:
            return self
        for child in self.children:
            found = child.find_node(node_id)
            if found is not None:
                return found
        return None

    def get_all_memory_ids(self) -> list[str]:
        all_ids = list(self.memory_ids)
        for child in self.children:
            all_ids.extend(child.get_all_memory_ids())
        return all_ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "children": [child.to_dict() for child in self.children],
            "memory_ids": list(self.memory_ids),
            "parent_id": self.parent_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemoryNode":
        node = cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            memory_ids=list(data.get("memory_ids", [])),
            parent_id=data.get("parent_id"),
        )
        for child_data in data.get("children", []):
            child = cls.from_dict(child_data)
            child.parent_id = node.id
            node.children.append(child)
        return node


@dataclass
class RetrievalResult:
    memory: MemoryItem
    relevance_score: float
    source_node_id: str
    reason: str = ""


class RetrievalAgent(ABC):
    def __init__(self, memory_store: "MemoryStore"):
        self.store = memory_store

    @abstractmethod
    def retrieve(self, query: str, top_k: int = 10) -> list[RetrievalResult]:
        raise NotImplementedError


class KeywordRetrievalAgent(RetrievalAgent):
    def retrieve(self, query: str, top_k: int = 10) -> list[RetrievalResult]:
        results: list[RetrievalResult] = []
        query_terms = {term for term in query.lower().split() if term}

        for memory in self.store.memories.values():
            content_lower = memory.get_display_content().lower()
            matches = sum(1 for term in query_terms if term in content_lower)
            score = matches / len(query_terms) if query_terms else 0.0

            for tag in memory.tags:
                if any(term in tag.lower() for term in query_terms):
                    score += 0.1

            if score > 0:
                results.append(
                    RetrievalResult(
                        memory=memory,
                        relevance_score=min(score, 1.0),
                        source_node_id=self._find_memory_node(memory.id) or self.store.root.id,
                        reason=f"Keyword match: {matches} terms",
                    )
                )

        results.sort(key=lambda item: item.relevance_score, reverse=True)
        return results[:top_k]

    def _find_memory_node(self, memory_id: str) -> str | None:
        return self._find_in_node(self.store.root, memory_id)

    def _find_in_node(self, node: MemoryNode, memory_id: str) -> str | None:
        if memory_id in node.memory_ids:
            return node.id
        for child in node.children:
            found = self._find_in_node(child, memory_id)
            if found is not None:
                return found
        return None


class LocalVectorRetrievalAgent(RetrievalAgent):
    """Local vector-based semantic retrieval using VectorEngine."""

    def __init__(self, memory_store: "MemoryStore"):
        super().__init__(memory_store)
        self.engine = VectorEngine()

    def retrieve(self, query: str, top_k: int = 10) -> list[RetrievalResult]:
        query_vector = self.engine.create_vector(query)
        if query_vector is None:
            # Fallback to keyword search if vector creation fails (e.g., missing model)
            return KeywordRetrievalAgent(self.store).retrieve(query, top_k)

        memories = list(self.store.memories.values())
        if not memories:
            return []

        # Ensure all memories have quantized vectors
        valid_memories: list[MemoryItem] = []
        codes_list: list[npt.NDArray[np.uint8]] = []
        signs_list: list[npt.NDArray[np.uint8]] = []

        for memory in memories:
            if memory.quantized_codes is None or memory.quantized_signs is None:
                if memory.vector is None:
                    memory.vector = self.engine.create_vector(memory.get_display_content())
                
                if memory.vector is not None:
                    memory.quantized_codes, memory.quantized_signs, _norm = self.engine.encode_quantized(memory.vector)
            
            if memory.quantized_codes is not None:
                valid_memories.append(memory)
                codes_list.append(memory.quantized_codes)
                signs_list.append(memory.quantized_signs)

        if not valid_memories:
            return KeywordRetrievalAgent(self.store).retrieve(query, top_k)

        all_codes = np.stack(codes_list)
        all_signs = np.stack(signs_list)

        scores = self.engine.quant_engine.compute_scores(query_vector, all_codes, all_signs)
        
        results: list[RetrievalResult] = []
        for memory, score in zip(valid_memories, scores, strict=False):
            if score > 0:
                results.append(
                    RetrievalResult(
                        memory=memory,
                        relevance_score=float(score),
                        source_node_id=self.store.root.id,  # Local search is flat across all memories
                        reason=f"Vector similarity: {score:.4f}",
                    )
                )

        results.sort(key=lambda item: item.relevance_score, reverse=True)
        return results[:top_k]


class HierarchicalRetrievalAgent(RetrievalAgent):
    """LLM-guided retrieval over the memory node hierarchy.

    The client is intentionally duck-typed so callers can provide any object
    with the memory retrieval methods used below. Batch methods are preferred
    for fewer LLM calls; single-item methods are used as a compatibility
    fallback when available.
    """

    def __init__(
        self,
        memory_store: "MemoryStore",
        llm_client: Any,
        max_branches_to_explore: int = 5,
        samples_per_node: int = 3,
        relevance_threshold: float = 0.3,
        branch_threshold: float = 0.2,
        max_depth: int = 10,
    ):
        super().__init__(memory_store)
        self.llm = llm_client
        self.max_branches_to_explore = max_branches_to_explore
        self.samples_per_node = samples_per_node
        self.relevance_threshold = relevance_threshold
        self.branch_threshold = branch_threshold
        self.max_depth = max_depth

    def retrieve(self, query: str, top_k: int = 10) -> list[RetrievalResult]:
        results: list[RetrievalResult] = []
        visited: set[str] = set()
        self._traverse_node(
            node=self.store.root,
            query=query,
            results=results,
            visited=visited,
            depth=0,
        )
        results.sort(key=lambda item: item.relevance_score, reverse=True)
        return results[:top_k]

    def _traverse_node(
        self,
        *,
        node: MemoryNode,
        query: str,
        results: list[RetrievalResult],
        visited: set[str],
        depth: int,
    ) -> None:
        if node.id in visited or depth > self.max_depth:
            return
        visited.add(node.id)

        node_memories = [
            (memory_id, self.store.memories[memory_id])
            for memory_id in node.memory_ids
            if memory_id in self.store.memories
        ]
        if node_memories:
            contents = [memory.get_display_content() for _, memory in node_memories]
            scores = self._evaluate_relevance_batch(query, contents)
            for (_, memory), (score, reason) in zip(node_memories, scores, strict=False):
                if score > self.relevance_threshold:
                    results.append(
                        RetrievalResult(
                            memory=memory,
                            relevance_score=score,
                            source_node_id=node.id,
                            reason=reason,
                        )
                    )

        if not node.children:
            return

        child_priorities = self._prioritize_children_batch(query, node.children)
        for child, priority, _reason in child_priorities[: self.max_branches_to_explore]:
            if priority > self.branch_threshold:
                self._traverse_node(
                    node=child,
                    query=query,
                    results=results,
                    visited=visited,
                    depth=depth + 1,
                )

    def _evaluate_relevance_batch(self, query: str, contents: list[str]) -> list[tuple[float, str]]:
        if not contents:
            return []
        if hasattr(self.llm, "evaluate_relevance_batch"):
            return self._normalize_scored_results(self.llm.evaluate_relevance_batch(query=query, contents=contents), len(contents))
        if hasattr(self.llm, "evaluate_relevance"):
            return [
                self._normalize_score_reason(self.llm.evaluate_relevance(query=query, content=content))
                for content in contents
            ]
        return [(self._keyword_relevance(query, content), "Keyword fallback") for content in contents]

    def _prioritize_children_batch(
        self,
        query: str,
        children: list[MemoryNode],
    ) -> list[tuple[MemoryNode, float, str]]:
        branches = []
        for child in children:
            sample_memories = []
            for memory_id in child.memory_ids[: self.samples_per_node]:
                memory = self.store.memories.get(memory_id)
                if memory is not None:
                    sample_memories.append(memory.get_display_content())
            branches.append(
                {
                    "node": child,
                    "name": child.name,
                    "description": child.description,
                    "samples": sample_memories,
                }
            )

        if hasattr(self.llm, "decide_branch_priority_batch"):
            scored = self._normalize_scored_results(
                self.llm.decide_branch_priority_batch(query=query, branches=branches),
                len(branches),
            )
        elif hasattr(self.llm, "decide_branch_priority"):
            scored = [
                self._normalize_score_reason(
                    self.llm.decide_branch_priority(
                        query=query,
                        node_name=branch["name"],
                        node_description=branch["description"],
                        sample_memories=branch["samples"],
                    )
                )
                for branch in branches
            ]
        else:
            scored = [
                (
                    self._keyword_relevance(
                        query,
                        " ".join([str(branch["name"]), str(branch["description"]), *branch["samples"]]),
                    ),
                    "Keyword fallback",
                )
                for branch in branches
            ]

        priorities = [
            (branch["node"], score, reason)
            for branch, (score, reason) in zip(branches, scored, strict=False)
        ]
        priorities.sort(key=lambda item: item[1], reverse=True)
        return priorities

    def _normalize_scored_results(self, raw_results: Any, expected_count: int) -> list[tuple[float, str]]:
        normalized = [self._normalize_score_reason(item) for item in list(raw_results or [])[:expected_count]]
        while len(normalized) < expected_count:
            normalized.append((0.0, "No score returned"))
        return normalized

    def _normalize_score_reason(self, raw_result: Any) -> tuple[float, str]:
        if isinstance(raw_result, tuple):
            score = raw_result[0] if raw_result else 0.0
            reason = raw_result[1] if len(raw_result) > 1 else ""
        else:
            score = raw_result
            reason = ""
        try:
            score_float = float(score)
        except (TypeError, ValueError):
            score_float = 0.0
        return max(0.0, min(score_float, 1.0)), str(reason)

    def _keyword_relevance(self, query: str, content: str) -> float:
        query_terms = {term for term in query.lower().split() if term}
        if not query_terms:
            return 0.0
        content_lower = content.lower()
        matches = sum(1 for term in query_terms if term in content_lower)
        return min(matches / len(query_terms), 1.0)


class ReorganizationPlan:
    def __init__(
        self,
        node_id: str,
        node_name: str,
        proposed_categories: list[dict[str, Any]],
        unassigned_memory_ids: list[str] | None = None,
    ):
        self.node_id = node_id
        self.node_name = node_name
        self.proposed_categories = proposed_categories
        self.unassigned_memory_ids = unassigned_memory_ids or []


class ReorganizationStrategy(ABC):
    @abstractmethod
    def should_reorganize(self, node: MemoryNode, store: "MemoryStore") -> bool:
        raise NotImplementedError

    @abstractmethod
    def create_plan(
        self,
        node: MemoryNode,
        store: "MemoryStore",
        llm_client: Any,
    ) -> ReorganizationPlan | None:
        raise NotImplementedError


class ThresholdReorganizationStrategy(ReorganizationStrategy):
    def __init__(self, threshold: int = 10, max_subcategories: int = 5, min_memories_per_category: int = 2):
        self.threshold = threshold
        self.max_subcategories = max_subcategories
        self.min_memories_per_category = min_memories_per_category

    def should_reorganize(self, node: MemoryNode, store: "MemoryStore") -> bool:
        return len(node.memory_ids) > self.threshold

    def create_plan(
        self,
        node: MemoryNode,
        store: "MemoryStore",
        llm_client: Any,
    ) -> ReorganizationPlan | None:
        if not self.should_reorganize(node, store):
            return None

        memories = [store.memories[mid] for mid in node.memory_ids if mid in store.memories]
        if len(memories) < self.min_memories_per_category:
            return None

        if llm_client and hasattr(llm_client, "analyze_and_categorize"):
            categories = llm_client.analyze_and_categorize(
                node_name=node.name,
                node_description=node.description,
                memories=[memory.get_display_content() for memory in memories],
                max_categories=self.max_subcategories,
                min_items_per_category=self.min_memories_per_category,
            )
        else:
            categories = _fallback_analyze_and_categorize(
                node_name=node.name,
                memories=memories,
                max_categories=self.max_subcategories,
                min_items_per_category=self.min_memories_per_category,
            )

        if not categories:
            return None

        proposed_categories: list[dict[str, Any]] = []
        assigned_ids: set[str] = set()

        for category in categories:
            category_memory_ids: list[str] = []
            for display_content in category.get("items", []):
                for memory in memories:
                    if memory.get_display_content() == display_content and memory.id not in assigned_ids:
                        category_memory_ids.append(memory.id)
                        assigned_ids.add(memory.id)
                        break

            if len(category_memory_ids) >= self.min_memories_per_category:
                proposed_categories.append(
                    {
                        "name": category["name"],
                        "description": category.get("description", ""),
                        "memory_ids": category_memory_ids,
                    }
                )

        unassigned = [mid for mid in node.memory_ids if mid not in assigned_ids and mid in store.memories]
        if not proposed_categories:
            return None

        return ReorganizationPlan(
            node_id=node.id,
            node_name=node.name,
            proposed_categories=proposed_categories,
            unassigned_memory_ids=unassigned,
        )


class LLMReorganizer:
    def __init__(self, store: "MemoryStore", llm_client: Any = None, strategy: ReorganizationStrategy | None = None):
        self.store = store
        self.llm = llm_client
        self.strategy = strategy or ThresholdReorganizationStrategy()
        self._reorganizing_nodes: set[str] = set()

    def check_and_reorganize(self, node_id: str | None = None) -> bool:
        reorganized = False
        if node_id:
            node = self.store.root.find_node(node_id)
            if node and self._reorganize_node(node):
                reorganized = True
        else:
            for node in self._collect_all_nodes(self.store.root):
                if self._reorganize_node(node):
                    reorganized = True
        return reorganized

    def _collect_all_nodes(self, node: MemoryNode) -> list[MemoryNode]:
        nodes = [node]
        for child in node.children:
            nodes.extend(self._collect_all_nodes(child))
        return nodes

    def _reorganize_node(self, node: MemoryNode) -> bool:
        if node.id in self._reorganizing_nodes:
            return False
        if not self.strategy.should_reorganize(node, self.store):
            return False

        self._reorganizing_nodes.add(node.id)
        try:
            plan = self.strategy.create_plan(node, self.store, self.llm)
            if not plan or not plan.proposed_categories:
                return False
            self._execute_plan(plan)
            return True
        finally:
            self._reorganizing_nodes.discard(node.id)

    def _execute_plan(self, plan: ReorganizationPlan) -> None:
        node = self.store.root.find_node(plan.node_id)
        if node is None:
            return

        existing_by_name = {child.name: child for child in node.children}
        for category in plan.proposed_categories:
            child_node = existing_by_name.get(category["name"])
            if child_node is None:
                child_node = node.add_child(category["name"], category.get("description", ""))
                existing_by_name[child_node.name] = child_node

            for memory_id in category["memory_ids"]:
                child_node.add_memory(memory_id)
                if memory_id in node.memory_ids:
                    node.memory_ids.remove(memory_id)

    def get_reorganization_candidates(self) -> list[MemoryNode]:
        return [
            node for node in self._collect_all_nodes(self.store.root)
            if self.strategy.should_reorganize(node, self.store)
        ]

    def preview_reorganization(self, node_id: str) -> dict[str, Any] | None:
        node = self.store.root.find_node(node_id)
        if node is None:
            return None
        plan = self.strategy.create_plan(node, self.store, self.llm)
        if plan is None:
            return None
        return {
            "node_id": plan.node_id,
            "node_name": plan.node_name,
            "current_memory_count": len(node.memory_ids),
            "proposed_categories": [
                {
                    "name": category["name"],
                    "description": category.get("description", ""),
                    "memory_count": len(category["memory_ids"]),
                }
                for category in plan.proposed_categories
            ],
            "unassigned_count": len(plan.unassigned_memory_ids),
        }


def _fallback_analyze_and_categorize(
    *,
    node_name: str,
    memories: list[MemoryItem],
    max_categories: int,
    min_items_per_category: int,
) -> list[dict[str, Any]]:
    buckets: dict[str, list[MemoryItem]] = {}

    for memory in memories:
        if memory.category:
            bucket_name = memory.category
        elif memory.tags:
            bucket_name = memory.tags[0]
        else:
            bucket_name = "general"
        buckets.setdefault(bucket_name, []).append(memory)

    ranked = sorted(buckets.items(), key=lambda item: (-len(item[1]), item[0]))
    categories: list[dict[str, Any]] = []
    for bucket_name, bucket_memories in ranked[:max_categories]:
        if len(bucket_memories) < min_items_per_category:
            continue
        categories.append(
            {
                "name": bucket_name,
                "description": f"Auto-grouped {bucket_name} findings under {node_name}",
                "items": [memory.get_display_content() for memory in bucket_memories],
            }
        )
    return categories


class MemoryStore:
    def __init__(
        self,
        reorganization_threshold: int = 50,
        retrieval_agent: RetrievalAgent | None = None,
        reorganization_strategy: ReorganizationStrategy | None = None,
        reorganization_llm: Any = None,
        auto_reorganize: bool = True,
    ):
        self.memories: dict[str, MemoryItem] = {}
        self.root = MemoryNode(name="root", description="Root of memory hierarchy")
        self.reorganization_threshold = reorganization_threshold
        self._is_reorganizing = False
        self.reorganization_llm = reorganization_llm
        self.auto_reorganize = auto_reorganize
        
        # Priority: Hierarchical (LLM) -> Local Vector -> Keyword
        if reorganization_llm is not None:
            self.retrieval_agent = HierarchicalRetrievalAgent(self, reorganization_llm)
        elif VectorEngine().llama is not None:
            self.retrieval_agent = LocalVectorRetrievalAgent(self)
        else:
            self.retrieval_agent = KeywordRetrievalAgent(self)

        self.reorganization_strategy = reorganization_strategy or ThresholdReorganizationStrategy(
            threshold=reorganization_threshold
        )
        self.reorganizer = LLMReorganizer(
            self,
            llm_client=self.reorganization_llm,
            strategy=self.reorganization_strategy,
        )

    def set_retrieval_agent(self, agent: RetrievalAgent) -> None:
        self.retrieval_agent = agent

    def set_reorganization_strategy(self, strategy: ReorganizationStrategy) -> None:
        self.reorganization_strategy = strategy
        self.reorganizer = LLMReorganizer(self, llm_client=self.reorganization_llm, strategy=strategy)

    def set_reorganization_llm(self, llm_client: Any) -> None:
        self.reorganization_llm = llm_client
        self.reorganizer = LLMReorganizer(self, llm_client=llm_client, strategy=self.reorganization_strategy)

    def add_memory(
        self,
        key: str | None = None,
        value: Any = None,
        category: str = "general",
        priority: MemoryPriority = MemoryPriority.MEDIUM,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        node_id: str | None = None,
    ) -> MemoryItem:
        memory = MemoryItem(
            key=key,
            value=value,
            category=category,
            priority=priority,
            tags=list(tags or []),
            metadata=dict(metadata or {}),
        )
        self.memories[memory.id] = memory

        target_node = self.root
        if node_id:
            found_node = self.root.find_node(node_id)
            if found_node is not None:
                target_node = found_node
        target_node.add_memory(memory.id)

        if self.auto_reorganize:
            self._auto_reorganize_from_node(target_node)
        return memory

    def _auto_reorganize_from_node(self, start_node: MemoryNode) -> None:
        if self._is_reorganizing:
            return
        self._is_reorganizing = True
        try:
            current: MemoryNode | None = start_node
            while current is not None:
                self.reorganizer.check_and_reorganize(current.id)
                current = self.root.find_node(current.parent_id) if current.parent_id else None
        finally:
            self._is_reorganizing = False

    def add_memory_auto(
        self,
        key: str,
        value: Any,
        category: str,
        llm_client: Any = None,
        priority: MemoryPriority = MemoryPriority.MEDIUM,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MemoryItem:
        selected_node_id: str | None = None
        nodes = self._get_all_non_root_nodes()
        if llm_client and nodes and hasattr(llm_client, "select_best_node"):
            nodes_data = [{"id": node.id, "name": node.name, "description": node.description} for node in nodes]
            selected_node_id = llm_client.select_best_node(f"{key}={value}", nodes_data)
        return self.add_memory(
            key=key,
            value=value,
            category=category,
            priority=priority,
            tags=tags,
            metadata=metadata,
            node_id=selected_node_id,
        )

    def add_memories_auto(
        self,
        memories: list[tuple[str, Any, str]],
        llm_client: Any = None,
        priority: MemoryPriority = MemoryPriority.MEDIUM,
    ) -> list[MemoryItem]:
        return [
            self.add_memory_auto(key, value, category, llm_client=llm_client, priority=priority)
            for key, value, category in memories
        ]

    def _get_all_non_root_nodes(self) -> list[MemoryNode]:
        nodes: list[MemoryNode] = []
        for child in self.root.children:
            nodes.extend(self._collect_nodes(child))
        return nodes

    def _collect_nodes(self, node: MemoryNode) -> list[MemoryNode]:
        nodes = [node]
        for child in node.children:
            nodes.extend(self._collect_nodes(child))
        return nodes

    def get_memory(self, memory_id: str) -> MemoryItem | None:
        return self.memories.get(memory_id)

    def update_memory(
        self,
        memory_id: str,
        *,
        value: Any = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        key: str | None = None,
    ) -> bool:
        memory = self.memories.get(memory_id)
        if memory is None:
            return False
        memory.update(value=value, tags=tags, metadata=metadata, key=key)
        return True

    def delete_memory(self, memory_id: str) -> bool:
        if memory_id not in self.memories:
            return False
        self._remove_memory_from_tree(self.root, memory_id)
        del self.memories[memory_id]
        return True

    def clear(self) -> None:
        self.memories.clear()
        self.root.memory_ids.clear()
        self.root.children.clear()

    def _remove_memory_from_tree(self, node: MemoryNode, memory_id: str) -> None:
        if memory_id in node.memory_ids:
            node.memory_ids.remove(memory_id)
        for child in node.children:
            self._remove_memory_from_tree(child, memory_id)

    def search_memories(self, query: str, top_k: int = 10) -> list[RetrievalResult]:
        try:
            return self.retrieval_agent.retrieve(query, top_k=top_k)
        except Exception:
            fallback = KeywordRetrievalAgent(self)
            return fallback.retrieve(query, top_k=top_k)

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        return [result.memory.to_dict() for result in self.search_memories(query, top_k=top_k)]

    def search_memories_filtered(
        self,
        *,
        category: str | None = None,
        tags: list[str] | None = None,
        priority: MemoryPriority | None = None,
        metadata_filter: dict[str, Any] | None = None,
    ) -> list[MemoryItem]:
        results: list[MemoryItem] = []
        for memory in self.memories.values():
            if category and memory.category != category:
                continue
            if tags and not all(tag in memory.tags for tag in tags):
                continue
            if priority and memory.priority.value < priority.value:
                continue
            if metadata_filter and any(memory.metadata.get(key) != value for key, value in metadata_filter.items()):
                continue
            results.append(memory)
        return results

    def mark_memory_resolved(self, memory_id: str, resolved: bool = True) -> bool:
        memory = self.memories.get(memory_id)
        if memory is None:
            return False
        memory.metadata["resolved"] = resolved
        memory.updated_at = datetime.now()
        return True

    def get_hypotheses(self, only_unresolved: bool = True) -> list[MemoryItem]:
        metadata_filter = {"resolved": False} if only_unresolved else None
        return self.search_memories_filtered(tags=["hypothesis"], metadata_filter=metadata_filter)

    def get_open_questions(self) -> list[MemoryItem]:
        return self.search_memories_filtered(tags=["open_question"])

    def get_confirmed_behaviors(self) -> list[MemoryItem]:
        return self.search_memories_filtered(category="ttp_candidate", tags=["confirmed"])

    def get_memories_by_node(self, node_id: str, include_children: bool = True) -> list[MemoryItem]:
        node = self.root.find_node(node_id)
        if node is None:
            return []
        memory_ids = node.get_all_memory_ids() if include_children else node.memory_ids
        return [self.memories[mid] for mid in memory_ids if mid in self.memories]

    def create_node(self, name: str, description: str = "", parent_id: str | None = None) -> MemoryNode:
        if parent_id is None:
            return self.root.add_child(name, description)
        parent = self.root.find_node(parent_id)
        if parent is None:
            raise ValueError(f"Parent node with ID {parent_id} not found")
        return parent.add_child(name, description)

    def move_memory_to_node(self, memory_id: str, node_id: str) -> bool:
        if memory_id not in self.memories:
            return False
        node = self.root.find_node(node_id)
        if node is None:
            return False
        self._remove_memory_from_tree(self.root, memory_id)
        node.add_memory(memory_id)
        return True

    def get_hierarchy(self) -> dict[str, Any]:
        return self.root.to_dict()

    def reorganize(
        self,
        llm_client: Any = None,
        threshold: int | None = None,
        max_subcategories: int = 5,
        min_memories_per_category: int = 2,
    ) -> bool:
        strategy = ThresholdReorganizationStrategy(
            threshold=threshold if threshold is not None else self.reorganization_threshold,
            max_subcategories=max_subcategories,
            min_memories_per_category=min_memories_per_category,
        )
        reorganizer = LLMReorganizer(self, llm_client=llm_client or self.reorganization_llm, strategy=strategy)
        return reorganizer.check_and_reorganize()

    def reorganize_node(
        self,
        node_id: str,
        llm_client: Any = None,
        max_subcategories: int = 5,
        min_memories_per_category: int = 2,
    ) -> bool:
        node = self.root.find_node(node_id)
        if node is None:
            return False
        strategy = ThresholdReorganizationStrategy(
            threshold=max(0, len(node.memory_ids) - 1),
            max_subcategories=max_subcategories,
            min_memories_per_category=min_memories_per_category,
        )
        reorganizer = LLMReorganizer(self, llm_client=llm_client or self.reorganization_llm, strategy=strategy)
        return reorganizer.check_and_reorganize(node_id)

    def preview_reorganization(
        self,
        node_id: str,
        llm_client: Any = None,
        min_memories_per_category: int = 2,
    ) -> dict[str, Any] | None:
        node = self.root.find_node(node_id)
        if node is None:
            return None
        strategy = ThresholdReorganizationStrategy(
            threshold=max(0, len(node.memory_ids) - 1),
            min_memories_per_category=min_memories_per_category,
        )
        reorganizer = LLMReorganizer(self, llm_client=llm_client or self.reorganization_llm, strategy=strategy)
        return reorganizer.preview_reorganization(node_id)

    def get_statistics(self) -> dict[str, Any]:
        category_counts: dict[str, int] = {}
        priority_counts: dict[str, int] = {}
        for memory in self.memories.values():
            category_counts[memory.category] = category_counts.get(memory.category, 0) + 1
            priority_key = memory.priority.name
            priority_counts[priority_key] = priority_counts.get(priority_key, 0) + 1
        return {
            "total_memories": len(self.memories),
            "categories": category_counts,
            "priorities": priority_counts,
            "reorganization_threshold": self.reorganization_threshold,
            "needs_reorganization": len(self.memories) >= self.reorganization_threshold,
        }

    def export_to_dict(self) -> dict[str, Any]:
        return {
            "memories": {memory_id: memory.to_dict() for memory_id, memory in self.memories.items()},
            "hierarchy": self.root.to_dict(),
            "reorganization_threshold": self.reorganization_threshold,
            "auto_reorganize": self.auto_reorganize,
        }

    def import_from_dict(self, data: dict[str, Any]) -> None:
        self.memories = {
            memory_id: MemoryItem.from_dict(memory_data)
            for memory_id, memory_data in data.get("memories", {}).items()
        }
        self.root = MemoryNode.from_dict(
            data.get("hierarchy", {"id": str(uuid4()), "name": "root", "description": "Root of memory hierarchy", "children": [], "memory_ids": []})
        )
        self.reorganization_threshold = data.get("reorganization_threshold", self.reorganization_threshold)
        self.auto_reorganize = data.get("auto_reorganize", self.auto_reorganize)
        self.retrieval_agent = KeywordRetrievalAgent(self)
        self.reorganization_strategy = ThresholdReorganizationStrategy(threshold=self.reorganization_threshold)
        self.reorganizer = LLMReorganizer(self, llm_client=self.reorganization_llm, strategy=self.reorganization_strategy)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemoryStore":
        store = cls(
            reorganization_threshold=data.get("reorganization_threshold", 50),
            auto_reorganize=data.get("auto_reorganize", True),
        )
        store.import_from_dict(data)
        return store


InMemoryBackboneStore = MemoryStore

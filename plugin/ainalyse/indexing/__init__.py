"""
AETHER Function Indexing package.

Provides LLM-powered classification and indexing of all non-trivial functions
in a binary, with resumable batching, atomic persistence, and configurable
tagging taxonomy.
"""

from .function_tagger import (
    DEFAULT_FUNCTION_TAGS,
    IMPORTANCE_LEVELS,
    ImportanceLevel,
    normalize_tag_id,
    resolve_tag,
)
from .dynamic_tag_manager import DynamicTagManager
from .function_index import BatchMetadata, FunctionEntry, FunctionIndex, get_index_filepath
from .function_index_manager import FunctionIndexManager, get_program_identifier
from .function_indexer import FunctionIndexer

__all__ = [
    # Tagger
    "DEFAULT_FUNCTION_TAGS",
    "IMPORTANCE_LEVELS",
    "ImportanceLevel",
    "normalize_tag_id",
    "resolve_tag",
    # Dynamic tags
    "DynamicTagManager",
    # Data classes
    "BatchMetadata",
    "FunctionEntry",
    "FunctionIndex",
    "get_index_filepath",
    # Manager / Indexer
    "FunctionIndexManager",
    "FunctionIndexer",
    "get_program_identifier",
]

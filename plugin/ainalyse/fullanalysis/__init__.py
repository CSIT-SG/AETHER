"""AETHER Fanalysis package shared imports."""

import os
import re
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import idaapi
except Exception:
    idaapi = None

try:
    import ida_funcs
except Exception:
    ida_funcs = None

try:
    import ida_kernwin
except Exception:
    ida_kernwin = None

try:
    import idc
except Exception:
    idc = None

from ainalyse import finalize_prompt
from ainalyse.indexing.function_index_manager import FunctionIndexManager
from ainalyse.indexing.function_indexer import FunctionIndexer

try:
    from ainalyse.qt_shim import QtWidgets
except Exception:
    QtWidgets = None

try:
    import tiktoken
except Exception:
    tiktoken = None

__all__ = [
    "os",
    "re",
    "textwrap",
    "time",
    "ThreadPoolExecutor",
    "as_completed",
    "idaapi",
    "ida_funcs",
    "ida_kernwin",
    "idc",
    "QtWidgets",
    "tiktoken",
    "finalize_prompt",
    "FunctionIndexManager",
    "FunctionIndexer",
]
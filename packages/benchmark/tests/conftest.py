"""Mock HeadlessExecutor before any test triggers its import.

``start_rpc_server.py`` imports ``HeadlessExecutor`` from
``aether_rpc.executors.headless_executor``, which does ``import idapro`` at
module load. Since test environments don't have IDA installed, we mock
the entire module so it never reaches the real ``idapro`` import.
"""
from unittest.mock import MagicMock
import sys

_MODULE = "aether_rpc.executors.headless_executor"
if _MODULE not in sys.modules:
    sys.modules[_MODULE] = MagicMock()

import contextlib
import io
import sys
import time
from collections.abc import Callable
from types import FrameType
from typing import Any

from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result

TraceFunc = Callable[[FrameType, str, Any], "TraceFunc | None"]


class ExecutionTimeoutError(BaseException):
    """BaseException so `except Exception` in executed code cannot swallow it."""


def _deadline_tracer(deadline: float, timeout: float) -> TraceFunc:
    def tracer(_frame: FrameType, _event: str, _arg: Any) -> TraceFunc:
        # re-raises on every traced line past the deadline, so bare `except:` cannot suppress it
        if time.monotonic() > deadline:
            raise ExecutionTimeoutError(f"Execution exceeded timeout of {timeout}s")
        return tracer

    return tracer


class ExecuteIDAPython(Capability):
    @property
    def name(self) -> str:
        return "execute_idapython"

    def execute(self, code: str, timeout: float = 10.0) -> Result[str]:
        """Executes a given Python code snippet in the IDA environment.

        The timeout is checked between Python lines, so it cannot interrupt a long-running native IDA call.

        Args:
            code: A string containing the Python code to execute.
            timeout: Maximum execution time in seconds.

        Returns:
            A Result object containing the output of the executed code or an error message.
        """
        # we need to inject this current module's globals into the exec environment to allow access to IDA's API
        # do not pass globals directly to exec, as it will overwrite the current module's globals
        global_scope = globals().copy()

        # Redirect stdout to capture print statements
        sysout = io.StringIO()
        prev_trace = sys.gettrace()
        # settrace is per-thread; this runs on the IDA main thread alongside exec
        sys.settrace(_deadline_tracer(time.monotonic() + timeout, timeout))
        try:
            with contextlib.redirect_stdout(sysout):
                exec(code, global_scope)
            return Ok(sysout.getvalue())
        except ExecutionTimeoutError as e:
            return Err(f"{e}\nPartial output:\n{sysout.getvalue()}")
        except Exception as e:
            self.logger.exception(
                "Failed to execute IDAPython code: %s\nPartial output: %s", e, sysout.getvalue()
            )
            return Err(str(e))
        finally:
            sys.settrace(prev_trace)

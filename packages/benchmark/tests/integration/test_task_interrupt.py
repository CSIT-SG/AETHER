"""Smoke test: interrupting a `Run` block cancels the task it wraps.

Interrupt delivery cannot be exercised in-process -- pytest owns the main thread's
SIGINT handler -- so this spawns a child mirroring `__main__.main`: a single
`asyncio.run` around an `async with Run(...)` block holding a task that sleeps
forever.
"""

import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

STARTUP_TIMEOUT_S = 60.0
SHUTDOWN_TIMEOUT_S = 30.0

CHILD_SCRIPT = """
import asyncio
import signal
import sys
from pathlib import Path

from aether_benchmark.utils.task import Run, Task

READY = Path(sys.argv[1])
CANCELLED = Path(sys.argv[2])


class SleepForeverTask(Task[[], None]):
    async def start(self) -> None:
        READY.write_text("ready", encoding="utf-8")
        await asyncio.Event().wait()

    async def cancel(self) -> None:
        CANCELLED.write_text("cancelled", encoding="utf-8")


async def _async_main() -> None:
    async with Run(SleepForeverTask)():
        await asyncio.sleep(3600)


if sys.platform == "win32":
    # A console Ctrl+C cannot be aimed at a single child on Windows, so the test
    # sends CTRL_BREAK. Map it to the handler Ctrl+C uses so the interpreter
    # raises KeyboardInterrupt exactly as it would for a real Ctrl+C.
    signal.signal(signal.SIGBREAK, signal.default_int_handler)

try:
    asyncio.run(_async_main())
except KeyboardInterrupt:
    pass
"""


def test_interrupt_cancels_a_sleeping_task(tmp_path: Path) -> None:
    script = tmp_path / "sleep_forever_main.py"
    script.write_text(CHILD_SCRIPT, encoding="utf-8")
    ready, cancelled = tmp_path / "ready", tmp_path / "cancelled"

    # Own process group, so signalling the child does not also hit pytest.
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    proc = subprocess.Popen(
        [sys.executable, str(script), str(ready), str(cancelled)],
        stderr=subprocess.PIPE,
        creationflags=creationflags,
    )

    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT_S
        while not ready.exists():
            assert proc.poll() is None, "child exited before starting the task"
            assert time.monotonic() < deadline, "child never started the task"
            time.sleep(0.05)

        proc.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
        try:
            _, stderr = proc.communicate(timeout=SHUTDOWN_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            pytest.fail(f"child did not exit within {SHUTDOWN_TIMEOUT_S}s of the interrupt")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    assert cancelled.exists(), (
        f"Task.cancel never ran on interrupt; child stderr:\n{stderr.decode(errors='replace')}"
    )

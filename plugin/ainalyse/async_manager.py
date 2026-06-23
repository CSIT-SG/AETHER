import asyncio
import os
import sys
import threading
import time
from concurrent.futures import Future
from typing import Callable, Coroutine, Optional

from .run_state import clear_current_run


class AsyncioThread(threading.Thread):
    """A thread for running the asyncio event loop."""
    def __init__(self, name: str = "AsyncWorker"):
        super().__init__(name=name)
        self.loop = None
        self.daemon = True
        self._ready = threading.Event()

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self._ready.set()
        self.loop.run_forever()

    def schedule_task(self, coro: Coroutine) -> Optional[Future]:
        """Schedules a coroutine to be run on the event loop."""
        if not self._ready.wait(timeout=5.0):
            print(f"[{self.name}] Error: Loop initialization timeout.")
            return None
            
        if self.loop and self.is_alive():
            return asyncio.run_coroutine_threadsafe(coro, self.loop)
        else:
            print(f"[{self.name}] Error: Loop is not running.")
            return None
    
    def stop(self):
        """Stop the event loop gracefully."""
        if self.loop and self.is_alive():
            self.loop.call_soon_threadsafe(self.loop.stop)


class AsyncThreadPool:
    """
    Manages multiple asyncio worker threads for concurrent async operations.
    """
    def __init__(self, num_workers: int = 2):
        """
        Create and start a pool of asyncio worker threads.

        Args:
            num_workers: Number of worker threads to create.
                Values < 1 are coerced to 1 to keep the pool usable.
        """
        normalized_worker_count = max(1, int(num_workers))
        self.workers = []
        self.next_worker_idx = 0
        self._lock = threading.Lock()
        
        print(f"[AsyncThreadPool] Creating pool with {normalized_worker_count} worker threads...")
        for i in range(normalized_worker_count):
            worker = AsyncioThread(name=f"AsyncWorker-{i}")
            worker.start()
            self.workers.append(worker)
        
        print(f"[AsyncThreadPool] Pool initialized with {len(self.workers)} workers")
    
    def get_worker(self, worker_id: Optional[int] = None) -> AsyncioThread:
        """
        Get a specific worker by ID, or round-robin through available workers.
        
        Args:
            worker_id: Specific worker index, or None for round-robin selection
        """
        if worker_id is not None:
            if 0 <= worker_id < len(self.workers):
                return self.workers[worker_id]
            else:
                print(f"[AsyncThreadPool] Invalid worker_id {worker_id}, using round-robin")
        
        # Round-robin selection
        with self._lock:
            worker = self.workers[self.next_worker_idx]
            self.next_worker_idx = (self.next_worker_idx + 1) % len(self.workers)
        return worker
    
    def schedule_task(self, coro: Coroutine, worker_id: Optional[int] = None) -> Optional[Future]:
        """
        Schedule a coroutine on a specific worker or round-robin.
        
        Args:
            coro: The coroutine to execute
            worker_id: Optional worker ID (0-based index), None for round-robin
        """
        worker = self.get_worker(worker_id)
        return worker.schedule_task(coro)
    
    # shutdown with drain wait
    def shutdown(self, wait: bool = True):
        print(f"[AsyncThreadPool] Shutting down {len(self.workers)} workers (wait={wait})...")
        for worker in self.workers:
            print(f"[AsyncThreadPool] Stopping worker {worker.name}...")
            worker.stop()
        
        if not wait:
            print("[AsyncThreadPool] Shutdown requested without wait. Workers will be terminated by OS (daemon=True).")
            return

        # Give workers up to 2s to finish their current iteration
        drain_timeout = 2.0
        deadline = time.monotonic() + drain_timeout
        print(f"[AsyncThreadPool] Waiting up to {drain_timeout}s for workers to drain...")
        
        for worker in self.workers:
            remaining = deadline - time.monotonic()
            if remaining > 0 and worker.is_alive():
                print(f"[AsyncThreadPool] Joining worker {worker.name} (remaining timeout: {remaining:.2f}s)...")
                worker.join(timeout=remaining)
            
            if worker.is_alive():
                print(f"[AsyncThreadPool] Worker {worker.name} still alive after drain wait. It will be terminated by the OS (daemon=True).")
            else:
                print(f"[AsyncThreadPool] Worker {worker.name} shut down gracefully.")
        print("[AsyncThreadPool] Shutdown sequence complete.")

    def worker_count(self) -> int:
        """Return the current number of worker threads in the pool."""
        return len(self.workers)


class DummyThread:
    def is_alive(self): return False
    def start(self): pass
    def stop(self): pass
    def schedule_task(self, coro): 
        _close_unscheduled_coroutine(coro)
        return None

class DummyPool:
    def __init__(self):
        self.workers = [DummyThread(), DummyThread()]
    def get_worker(self, worker_id=None): return self.workers[0]
    def schedule_task(self, coro, worker_id=None): 
        _close_unscheduled_coroutine(coro)
        return None
    def shutdown(self): pass
    def worker_count(self): return len(self.workers)


# Lazily create the thread pool to avoid import-time side effects during plugin load.
ASYNC_POOL = None
ASYNC_WORKER = None
# Backward-compatible alias: exposes all workers for new call sites.
ASYNC_WORKERS = []

# Pipeline worker IDs for clarity
PIPELINE_WORKER = 0
UI_WORKER = 1

# Keep a default >= 2 so dedicated pipeline/UI workers can run concurrently.
DEFAULT_ASYNC_WORKER_COUNT = 2

ASYNC_SHUTTING_DOWN = False

PIPELINE_STATE = {
    "is_running": False,
    "current_task_future": None
}


def ensure_async_pool(allow_reinit: bool = False) -> AsyncThreadPool:
    """
    Create (if needed) and return the shared async worker pool.
    """
    global ASYNC_POOL, ASYNC_WORKER, ASYNC_WORKERS, ASYNC_SHUTTING_DOWN
    
    if ASYNC_SHUTTING_DOWN and not allow_reinit:
        return DummyPool()

    if allow_reinit:
        ASYNC_SHUTTING_DOWN = False

    if ASYNC_POOL is None:
        configured_worker_count = _get_configured_worker_count()
        print("[AETHER] [Async Manager] Creating shared asyncio thread pool...")
        ASYNC_POOL = AsyncThreadPool(num_workers=configured_worker_count)
        ASYNC_WORKER = ASYNC_POOL.workers[PIPELINE_WORKER]
        ASYNC_WORKERS = ASYNC_POOL.workers
    return ASYNC_POOL


def _close_unscheduled_coroutine(coro: Coroutine):
    """Close a coroutine that was never scheduled to avoid runtime warnings."""
    if asyncio.iscoroutine(coro):
        try:
            coro.close()
        except Exception:
            pass


def _get_configured_worker_count() -> int:
    """
    Resolve worker count from environment with safe fallbacks.

    Returns:
        A positive worker count. Falls back to DEFAULT_ASYNC_WORKER_COUNT
        when the environment variable is missing or invalid.
    """
    raw_value = os.getenv("AETHER_ASYNC_WORKERS", str(DEFAULT_ASYNC_WORKER_COUNT)).strip()
    try:
        value = int(raw_value)
        if value < 1:
            raise ValueError("worker count must be >= 1")
        return value
    except (TypeError, ValueError):
        print(
            "[AETHER] [Async Manager] Invalid AETHER_ASYNC_WORKERS="
            f"'{raw_value}', falling back to {DEFAULT_ASYNC_WORKER_COUNT}."
        )
        return DEFAULT_ASYNC_WORKER_COUNT


def _resolve_ui_worker_id(pool: AsyncThreadPool) -> int:
    """
    Return the worker index used for UI tasks.

    If the pool has only one worker, UI tasks gracefully fall back to the
    pipeline worker to preserve behavior instead of failing.
    """
    if pool and pool.worker_count() > UI_WORKER:
        return UI_WORKER
    return PIPELINE_WORKER


def get_primary_worker() -> AsyncioThread:
    """
    Return the dedicated pipeline worker thread.

    This function is intentionally preserved for backward compatibility with
    existing plugin startup code.
    """
    pool = ensure_async_pool()
    return pool.workers[PIPELINE_WORKER]


def get_worker(worker_id: Optional[int] = None) -> AsyncioThread:
    """
    Return a specific worker by index or a round-robin selected worker.

    Args:
        worker_id: Worker index (0-based). If None, uses round-robin.
    """
    pool = ensure_async_pool()
    return pool.get_worker(worker_id)

def use_async_worker(name: Optional[str] = None):
    """
    Decorator for async functions that automatically manages `PIPELINE_STATE`.
    Ensures `is_running` is set/cleared and handles cleanup properly.
    
    Args:
        name: Optional custom name for logging. If not provided, uses function name.
        
    Usage:
    ```python
        @use_async_worker()
        async def my_function():
            pass
            
        @use_async_worker("CustomName")
        async def another_function():
            pass
    ```
    """
    def decorator(async_function):
        async def wrapper(*args, **kwargs):
            display_name = name if name else async_function.__name__
            PIPELINE_STATE["is_running"] = True
            try:
                result = await async_function(*args, **kwargs)
                return result
            finally:
                print(f"[{display_name}] Cleaning up pipeline state.")
                ctx_path = clear_current_run()
                if ctx_path:
                    try:
                        if os.path.exists(ctx_path):
                            os.remove(ctx_path)
                    except Exception as e:
                        print(f"[{display_name}] Error deleting ctx file '{ctx_path}': {e}")
                PIPELINE_STATE["current_task_future"] = None
                PIPELINE_STATE["is_running"] = False
        
        return wrapper
    return decorator

def start_pipeline(pipeline_coroutine: Coroutine):
    """
    Starts a pipeline coroutine on the dedicated pipeline worker thread.
    This is the generic entry point for any long-running task.
    """
    global ASYNC_SHUTTING_DOWN

    # If it was previously shut down, try to re-init if requested.
    # This helps recover from transient shutdown states if the plugin is still active.
    if ASYNC_SHUTTING_DOWN:
        print("[Async Manager] Pipeline requested while shut down. Attempting recovery...")
        ensure_async_pool(allow_reinit=True)

    if ASYNC_SHUTTING_DOWN:
        print("[Async Manager] Rejecting pipeline start: async runtime is shutting down.")
        _close_unscheduled_coroutine(pipeline_coroutine)
        return False

    if PIPELINE_STATE["is_running"]:
        # Check if the previous task is actually done but the state wasn't cleared
        future_handle = PIPELINE_STATE["current_task_future"]
        if future_handle and future_handle.done():
            print("[Async Manager] Found stale pipeline state (task is done). Resetting.")
            PIPELINE_STATE["is_running"] = False
            PIPELINE_STATE["current_task_future"] = None
        else:
            print("[Async Manager] Cannot start: a pipeline is already running.")
            _close_unscheduled_coroutine(pipeline_coroutine)
            return False

    print("[Async Manager] Scheduling pipeline to run on dedicated worker thread.")
    
    # Schedule on the pipeline worker (worker 0)
    pool = ensure_async_pool()
    if pool is None:
        _close_unscheduled_coroutine(pipeline_coroutine)
        return False

    future_handle = pool.schedule_task(pipeline_coroutine, worker_id=PIPELINE_WORKER)
    
    if future_handle:
        PIPELINE_STATE["current_task_future"] = future_handle
        PIPELINE_STATE["is_running"] = True
        return True
    else:
        print("[Async Manager] Failed to schedule pipeline.")
        _close_unscheduled_coroutine(pipeline_coroutine)
        return False


def cancel_pipeline():
    """
    Requests cancellation of the currently running pipeline.
    """
    global ASYNC_POOL
    if ASYNC_POOL is None:
        return

    future_handle = PIPELINE_STATE["current_task_future"]

    if not PIPELINE_STATE["is_running"] or future_handle is None:
        return

    print("[Async Manager] Sending cancellation request to the running pipeline...")
    future_handle.cancel()
    print("[Async Manager] Cancellation request sent.")


def schedule_ui_task(coro: Coroutine) -> Optional[Future]:
    """
    Schedule a UI-related async task on the UI worker thread.
    This won't block the pipeline worker.
    """
    global ASYNC_SHUTTING_DOWN
    
    if ASYNC_SHUTTING_DOWN:
        print("[Async Manager] UI task requested while shut down. Attempting recovery...")
        ensure_async_pool(allow_reinit=True)

    if ASYNC_SHUTTING_DOWN:
        print("[Async Manager] Rejecting UI task: async runtime is shutting down.")
        _close_unscheduled_coroutine(coro)
        return None

    pool = ensure_async_pool()
    if pool is None:
        _close_unscheduled_coroutine(coro)
        return None
        
    worker_id = _resolve_ui_worker_id(pool)
    return pool.schedule_task(coro, worker_id=worker_id)


def shutdown_async_runtime(cancel_running_pipeline: bool = True):
    """
    Shut down shared async runtime and reject new scheduling.

    This should be called during plugin teardown before widgets are destroyed.
    """
    global ASYNC_POOL, ASYNC_WORKER, ASYNC_WORKERS, ASYNC_SHUTTING_DOWN

    if ASYNC_SHUTTING_DOWN and ASYNC_POOL is None:
        return

    print("[Async Manager] shutdown_async_runtime: Starting shutdown sequence...")
    # import traceback
    # traceback.print_stack()

    ASYNC_SHUTTING_DOWN = True

    if cancel_running_pipeline:
        print("[Async Manager] shutdown_async_runtime: Cancelling pipelines...")
        try:
            cancel_pipeline()
        except Exception as e:
            print(f"[Async Manager] Warning: Pipeline cancellation failed: {e}")

    pool = ASYNC_POOL
    if pool is not None:
        print(f"[Async Manager] shutdown_async_runtime: Shutting down pool with {len(pool.workers)} workers...")
        # DO NOT join threads during IDA exit. Joining can cause deadlocks if 
        # a worker is stuck in an IDA API call (execute_sync). 
        # Since they are daemon threads, they will be cleaned up by the OS 
        # when the IDA process terminates.
        try:
            pool.shutdown(wait=False)
        except Exception as e:
            print(f"[Async Manager] Warning: Pool shutdown failed: {e}")

    ASYNC_POOL = None
    ASYNC_WORKER = None
    ASYNC_WORKERS = []
    
    # Reset pipeline state
    try:
        if PIPELINE_STATE["current_task_future"]:
            PIPELINE_STATE["current_task_future"].cancel()
    except Exception:
        pass
    PIPELINE_STATE["current_task_future"] = None
    PIPELINE_STATE["is_running"] = False
    
    print("[Async Manager] shutdown_async_runtime: Shutdown sequence complete.")


def run_async_in_ida(coro: Coroutine):
    """
    Run an async coroutine synchronously in IDA's context.
    This is a blocking call that waits for the coroutine to complete.
    
    On Windows, sets the appropriate event loop policy for compatibility.
    This is useful for running async code from synchronous IDA callbacks.
    
    Args:
        coro: The coroutine to execute
        
    Returns:
        The result of the coroutine execution
    """
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    return asyncio.run(coro)


def run_in_background(func: Callable, *args, **kwargs) -> threading.Thread:
    """
    Run a synchronous function in a background daemon thread.
    This is a convenience wrapper for the common pattern of:
        threading.Thread(target=func, daemon=True).start()
    
    Args:
        func: The function to run in the background
        *args: Positional arguments to pass to func
        **kwargs: Keyword arguments to pass to func
        
    Returns:
        The started Thread object
        
    Example:
        def my_analysis():
            result = run_async_in_ida(some_async_function())
            print(result)
        
        run_in_background(my_analysis)
    """
    thread = threading.Thread(target=func, args=args, kwargs=kwargs, daemon=True)
    thread.start()
    return thread

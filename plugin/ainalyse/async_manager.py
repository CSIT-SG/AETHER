import asyncio
import sys
import threading
from concurrent.futures import Future
from typing import Callable, Coroutine, Optional


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
        self.workers = []
        self.next_worker_idx = 0
        self._lock = threading.Lock()
        
        print(f"[AsyncThreadPool] Creating pool with {num_workers} worker threads...")
        for i in range(num_workers):
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
    
    def shutdown(self):
        """Stop all worker threads gracefully."""
        print("[AsyncThreadPool] Shutting down all workers...")
        for worker in self.workers:
            worker.stop()


# Create a thread pool with 2 workers:
# - Worker 0: Dedicated to long-running pipelines (struct creation, analysis, etc.)
# - Worker 1: Available for quick tasks (UI interactions, testing, etc.)
print("[AETHER] [Async Manager] Creating shared asyncio thread pool...")
ASYNC_POOL = AsyncThreadPool(num_workers=2)

ASYNC_WORKER = ASYNC_POOL.workers[0]

# Pipeline worker IDs for clarity
PIPELINE_WORKER = 0
UI_WORKER = 1

PIPELINE_STATE = {
    "is_running": False,
    "current_task_future": None
}

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
                PIPELINE_STATE["current_task_future"] = None
                PIPELINE_STATE["is_running"] = False
        
        return wrapper
    return decorator

def start_pipeline(pipeline_coroutine: Coroutine):
    """
    Starts a pipeline coroutine on the dedicated pipeline worker thread.
    This is the generic entry point for any long-running task.
    """
    if PIPELINE_STATE["is_running"]:
        print("[Async Manager] Cannot start: a pipeline is already running.")
        return

    print("[Async Manager] Scheduling pipeline to run on dedicated worker thread.")
    
    # Schedule on the pipeline worker (worker 0)
    future_handle = ASYNC_POOL.schedule_task(pipeline_coroutine, worker_id=PIPELINE_WORKER)
    
    if future_handle:
        PIPELINE_STATE["current_task_future"] = future_handle
        PIPELINE_STATE["is_running"] = True
    else:
        print("[Async Manager] Failed to schedule pipeline.")


def cancel_pipeline():
    """
    Requests cancellation of the currently running pipeline.
    """
    future_handle = PIPELINE_STATE["current_task_future"]

    if not PIPELINE_STATE["is_running"] or future_handle is None:
        print("[Async Manager] Nothing to cancel.")
        return

    print("[Async Manager] Sending cancellation request to the running pipeline...")
    future_handle.cancel()


def schedule_ui_task(coro: Coroutine) -> Optional[Future]:
    """
    Schedule a UI-related async task on the UI worker thread.
    This won't block the pipeline worker.
    
    Args:
        coro: The coroutine to execute
        
    Returns:
        Future object for the scheduled task, or None if scheduling failed
    """
    return ASYNC_POOL.schedule_task(coro, worker_id=UI_WORKER)


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
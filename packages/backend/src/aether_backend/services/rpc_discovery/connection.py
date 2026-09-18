import asyncio
import random
from pathlib import Path
from typing import Any, NamedTuple

import rpyc
from aether_utils.logger import get_logger

from .constants import (
    BACKOFF_BASE,
    BACKOFF_JITTER,
    BACKOFF_MAX,
    CONNECT_RETRIES,
    CONNECT_TIMEOUT,
    PING_TIMEOUT,
    RPYC_CONFIG,
)

logger = get_logger("rpc-registry")


class RpcConnectionEntry(NamedTuple):
    rpc_id: str
    conn: rpyc.Connection
    root: Any
    port: int
    path: Path


def _jitter(value: float) -> float:
    return value * (1.0 + random.uniform(-BACKOFF_JITTER, BACKOFF_JITTER))


def _backoff(attempt: int) -> float:
    """Exponential backoff with full jitter, capped at BACKOFF_MAX."""
    raw = BACKOFF_BASE * (2**attempt)
    return _jitter(min(raw, BACKOFF_MAX))


async def connect_with_backoff(
    *,
    rpc_id: str,
    port: int,
    path: Path,
) -> RpcConnectionEntry | None:
    """
    Try to open an RPyC connection, retrying with exponential backoff.
    Returns None if all attempts are exhausted.
    """
    for attempt in range(CONNECT_RETRIES):
        try:
            conn = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: rpyc.connect(
                        "127.0.0.1",
                        port,
                        config=RPYC_CONFIG,
                    ),
                ),
                timeout=CONNECT_TIMEOUT,
            )
            logger.info(
                "Connected to RPC service %r on port %d (attempt %d)",
                rpc_id,
                port,
                attempt + 1,
            )
            return RpcConnectionEntry(
                conn=conn, root=conn.root, rpc_id=rpc_id, port=port, path=path
            )

        except TimeoutError:
            logger.warning(
                "Timeout connecting to %r (port %d), attempt %d/%d",
                rpc_id,
                port,
                attempt + 1,
                CONNECT_RETRIES,
            )
        except Exception:
            logger.warning(
                "Error connecting to %r (port %d), attempt %d/%d",
                rpc_id,
                port,
                attempt + 1,
                CONNECT_RETRIES,
                exc_info=True,
            )

        if attempt < CONNECT_RETRIES - 1:
            delay = _backoff(attempt)
            logger.debug("Retrying %r in %.2fs …", rpc_id, delay)
            await asyncio.sleep(delay)

    logger.error(
        "Giving up on RPC service %r after %d attempts",
        rpc_id,
        CONNECT_RETRIES,
    )
    return None


def safe_close(conn: rpyc.Connection) -> None:
    try:
        conn.close()
    except Exception as e:
        logger.warning("Error closing connection to %r: %s", conn, e, exc_info=True)


async def ping(entry: RpcConnectionEntry) -> bool:
    """
    Return True if the connection is still alive.
    RPyC's ping() is a synchronous call; run it in a thread executor with a
    timeout so it cannot block the event loop.
    """
    try:
        await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, entry.conn.ping),
            timeout=PING_TIMEOUT,
        )
        return True
    except Exception:
        return False

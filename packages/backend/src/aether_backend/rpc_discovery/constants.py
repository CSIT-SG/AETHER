from typing import Any

BACKOFF_BASE: float = 0.5  # seconds before first retry
BACKOFF_MAX: float = 60.0  # cap per attempt
BACKOFF_JITTER: float = 0.25  # ±25 % random jitter
CONNECT_RETRIES: int = 5  # attempts before giving up on one service
CONNECT_TIMEOUT: float = 5.0  # per-attempt socket timeout (seconds)
PING_TIMEOUT: float = 3.0  # heartbeat ping deadline
RPYC_CONFIG: dict[str, Any] = {
    "allow_public_attrs": True,
    "allow_pickle": True,
    "sync_request_timeout": CONNECT_TIMEOUT,
}

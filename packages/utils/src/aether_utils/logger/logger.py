import logging


class NamespacedLogger(logging.Logger):
    """
    A Logger subclass that prefixes all messages with [aether.<namespace>].

    Args:
        name:      Internal logger name (used by Python's logging registry).
        namespace: Optional sub-namespace appended to 'aether', e.g. 'auth'
                   produces [aether.auth].
        level:     Logging level (default: logging.NOTSET).
    """

    def __init__(self, name: str, namespace: str | None = None, level: int = logging.NOTSET):
        super().__init__(name, level)
        self.namespace = namespace

        prefix = f"aether.{namespace}" if namespace else "aether"

        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(f"[{prefix}] %(levelname)s: %(message)s"))
        self.addHandler(handler)
        self.propagate = False  # prevent double-printing to root logger


def get_logger(namespace: str | None = None, level: int = logging.DEBUG) -> NamespacedLogger:
    """Convenience factory — mirrors logging.getLogger() but returns a NamespacedLogger."""
    
    internal_name = f"aether.{namespace}" if namespace else "aether"
    logger = NamespacedLogger(internal_name, namespace=namespace, level=level)
    return logger

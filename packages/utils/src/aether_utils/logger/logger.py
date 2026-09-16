import logging


class ColorFormatter(logging.Formatter):
    """Formatter that colorizes only the namespace prefix and level name."""

    COLORS = {
        logging.DEBUG: "\033[36m",  # cyan
        logging.INFO: "\033[32m",  # green
        logging.WARNING: "\033[33m",  # yellow
        logging.ERROR: "\033[31m",  # red
        logging.CRITICAL: "\033[1;31m",  # bold red
    }
    RESET = "\033[0m"

    def __init__(self, prefix: str, use_color: bool = True):
        super().__init__()
        self.prefix = prefix
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, "") if self.use_color else ""
        reset = self.RESET if self.use_color else ""

        prefix = f"{color}[{self.prefix}]{reset}"
        levelname = f"{color}{record.levelname}{reset}"

        message = record.getMessage()
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            message = f"{message}\n{record.exc_text}"

        return f"{prefix} {levelname}: {message}"


class NamespacedLogger(logging.Logger):
    """
    A Logger subclass that prefixes all messages with [aether.<namespace>]
    and colorizes the prefix + level name by log level.

    Args:
        name:      Internal logger name (used by Python's logging registry).
        namespace: Optional sub-namespace appended to 'aether', e.g. 'auth'
                   produces [aether.auth].
        level:     Logging level (default: logging.INFO).
        use_color: Whether to colorize output (default: True). Set False when
                   writing to a file or a non-TTY stream.
    """

    def __init__(
        self,
        name: str,
        namespace: str | None = None,
        level: int = logging.INFO,
        use_color: bool = False,
    ):
        super().__init__(name, level)
        self.namespace = namespace
        prefix = f"aether.{namespace}" if namespace else "aether"

        handler = logging.StreamHandler()
        handler.setFormatter(ColorFormatter(prefix, use_color=use_color))
        self.addHandler(handler)
        self.propagate = False  # prevent double-printing to root logger


def get_logger(
    namespace: str | None = None,
    level: int = logging.DEBUG,
    use_color: bool = False,
) -> NamespacedLogger:
    """Convenience factory — mirrors logging.getLogger() but returns a NamespacedLogger."""
    internal_name = f"aether.{namespace}" if namespace else "aether"
    logger = NamespacedLogger(internal_name, namespace=namespace, level=level, use_color=use_color)
    return logger

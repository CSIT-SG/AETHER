from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def _hexify(value):
    return f"{value:#x}" if value is not None else "<none>"


_TEMPLATES_DIR = Path(__file__).resolve().parent / "prompts"

_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=False,
)
_env.filters["hexify"] = _hexify


TASK_TEMPLATE = _env.get_template("user_prompt.jinja")

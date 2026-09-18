from pathlib import Path

from aether_utils.get_content import get_content
from jinja2 import Environment, Template

_env = Environment(
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=False,
)


def get_template(filename: str) -> Template:
    source = get_content(Path(__file__).resolve().parent, filename)
    return _env.from_string(source)

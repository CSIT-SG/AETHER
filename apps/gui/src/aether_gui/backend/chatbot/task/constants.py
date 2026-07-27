from pathlib import Path

from jinja2 import Environment, FileSystemLoader, Template

_TEMPLATES_DIR = Path(__file__).resolve().parent / "prompts"

_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=False,
)


def get_template(filename: str) -> Template:
    return _env.get_template(filename)

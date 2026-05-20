import os

from aether_gui.features.chatbot.ui.stylesheet import FORMATTING_PATH
from jinja2 import Environment, FileSystemLoader


class ThemeManager:
    def __init__(self) -> None:
        self.themes_dir = os.path.dirname(FORMATTING_PATH)
        self.current_theme = ""
        self.load_theme(self.get_dark_mode())

    def get_dark_mode(self) -> str:
        is_dark = "dark" in os.environ.get("IDA_THEME", "").lower()
        return "dark" if is_dark else "light"

    def load_theme(self, theme: str) -> None:
        file_loader = FileSystemLoader(self.themes_dir)
        env = Environment(loader=file_loader)

        template = env.get_template(FORMATTING_PATH.name)

        self.current_theme = template.render(theme=theme)

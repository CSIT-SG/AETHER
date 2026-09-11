from pathlib import Path

from aether_gui.utils.ui import StyledComponent
from PySide6.QtWidgets import QHBoxLayout, QLabel, QProgressBar


class ResponseStatus(StyledComponent):  # type: ignore[misc]
    def init_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        progress = QProgressBar(self)
        progress.setObjectName("ResponseProgress")
        progress.setRange(0, 0)
        progress.setTextVisible(False)
        progress.setFixedSize(32, 4)
        progress.setAccessibleName("AETHER is responding")
        layout.addWidget(progress)
        layout.addWidget(QLabel("AETHER is responding…", self))
        layout.addStretch()

        policy = self.sizePolicy()
        policy.setRetainSizeWhenHidden(True)
        self.setSizePolicy(policy)
        self.hide()

    def style_file(self) -> Path | None:
        return Path(__file__).resolve().parent / "styles.qss.jinja"

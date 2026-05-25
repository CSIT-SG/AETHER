# Plugin Guide

## Minimal Steps

1. Create a class that implements `AbstractComponentPlugin`.
2. Implement `name`, `install()`, and `uninstall()`.
3. (Optional) Override `priority` to control install order.
4. Pass the plugin instance when constructing your widget.

## Example 1: Add a Label

```python
from PySide6.QtWidgets import QLabel, QWidget

from aether_gui.utils.ui.plugins import AbstractComponentPlugin


class HelloLabelPlugin(AbstractComponentPlugin):
    @property
    def name(self) -> str:
        return "hello-label"

    def install(self, widget: QWidget) -> None:
        widget._hello_label = QLabel("Hello", widget)
        widget._hello_label.move(8, 8)

    def uninstall(self, widget: QWidget) -> None:
        label = getattr(widget, "_hello_label", None)
        if label is not None:
            label.deleteLater()
            delattr(widget, "_hello_label")
```

Behavior: a small "Hello" label appears at the top-left of the widget and is removed when the widget closes.

## Example 2: Timer-Driven Status Text

```python
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QLabel, QWidget

from aether_gui.utils.ui.plugins import AbstractComponentPlugin


class TickingLabelPlugin(AbstractComponentPlugin):
    @property
    def name(self) -> str:
        return "ticking-label"

    def install(self, widget: QWidget) -> None:
        widget._tick_count = 0
        widget._tick_label = QLabel("0", widget)
        widget._tick_label.move(8, 8)

        def _tick() -> None:
            widget._tick_count += 1
            widget._tick_label.setText(str(widget._tick_count))

        widget._tick_timer = QTimer(widget)
        widget._tick_timer.timeout.connect(_tick)
        widget._tick_timer.start(1000)

    def uninstall(self, widget: QWidget) -> None:
        timer = getattr(widget, "_tick_timer", None)
        if timer is not None:
            timer.stop()
            timer.deleteLater()
            delattr(widget, "_tick_timer")

        label = getattr(widget, "_tick_label", None)
        if label is not None:
            label.deleteLater()
            delattr(widget, "_tick_label")

        if hasattr(widget, "_tick_count"):
            delattr(widget, "_tick_count")
```

Behavior: a counter label increments once per second and stops updating when the widget closes.

## Example 3: Priority and Layout Ordering

```python
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from aether_gui.utils.ui.plugins import AbstractComponentPlugin


class LayoutPlugin(AbstractComponentPlugin):
    @property
    def name(self) -> str:
        return "layout"

    @property
    def priority(self) -> int:
        return 10

    def install(self, widget: QWidget) -> None:
        widget._layout = QVBoxLayout(widget)
        widget.setLayout(widget._layout)

    def uninstall(self, widget: QWidget) -> None:
        layout = getattr(widget, "_layout", None)
        if layout is not None:
            layout.deleteLater()
            delattr(widget, "_layout")


class BadgePlugin(AbstractComponentPlugin):
    @property
    def name(self) -> str:
        return "badge"

    def install(self, widget: QWidget) -> None:
        label = QLabel("Ready", widget)
        if hasattr(widget, "_layout"):
            widget._layout.addWidget(label)
        else:
            label.move(8, 8)
        widget._badge_label = label

    def uninstall(self, widget: QWidget) -> None:
        label = getattr(widget, "_badge_label", None)
        if label is not None:
            label.deleteLater()
            delattr(widget, "_badge_label")
```

Behavior: `LayoutPlugin` installs first, so `BadgePlugin` can add its label to the vertical layout. If the layout is missing, the label falls back to absolute positioning.

## Using the Plugin

```python
from aether_gui.utils.ui import StyledComponent


class MyWidget(StyledComponent):
    def __init__(self, parent=None):
        super().__init__(
            parent,
            plugins=[LayoutPlugin(), BadgePlugin(), TickingLabelPlugin(), HelloLabelPlugin()],
        )

    def init_ui(self) -> None:
        pass
```

Behavior: the widget shows a "Ready" badge in a vertical layout, a ticking counter label, and a static "Hello" label.

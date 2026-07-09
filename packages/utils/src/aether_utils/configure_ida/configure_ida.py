import os
import sys


def configure_ida(ida_install_dir: str) -> None:
    os.environ.setdefault("IDADIR", ida_install_dir)
    if ida_install_dir not in sys.path:
        sys.path.insert(0, ida_install_dir)

from os.path import basename

import ida_nalt


class IDBContext:
    def __init__(self):
        self._path = ida_nalt.get_input_file_path()

    @property
    def binary_name(self) -> str:
        """Get the file name of the loaded binary, without the path."""
        return basename(self._path)

    @property
    def binary_path(self) -> str:
        """Get the absolute file path of the loaded binary."""
        return self._path

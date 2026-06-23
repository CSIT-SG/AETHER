"""
Qt shim to handle PyQt5 (IDA < 9) and PySide6 (IDA >= 9) compatibility.
"""
import sys

try:
    # Prefer PySide6 for IDA 9+
    from PySide6 import QtCore, QtGui, QtWidgets
    QT_VERSION = 6
    USING_PYSIDE = True
except ImportError:
    try:
        # Fallback to PyQt5 for older versions
        from PyQt5 import QtCore, QtGui, QtWidgets
        QT_VERSION = 5
        USING_PYSIDE = False
    except ImportError:
        # Emergency fallback to ensure basic symbols are defined
        QtCore = None
        QtGui = None
        QtWidgets = None
        QT_VERSION = 0
        USING_PYSIDE = False

def is_deleted(obj):
    if obj is None:
        return True

    # PySide6 (IDA 9+)
    try:
        import shiboken6
        return not shiboken6.isValid(obj)
    except ImportError:
        pass

    # PySide2 (legacy)
    try:
        import shiboken2
        return not shiboken2.isValid(obj)
    except ImportError:
        pass

    # PyQt5 fallback
    try:
        import sip
        return sip.isdeleted(obj)
    except ImportError:
        pass

    # Last resort — genuinely safe attribute probe
    try:
        obj.objectName()
        return False
    except RuntimeError:
        return True
    except Exception:
        return True

# --- Compatibility Aliases ---
if USING_PYSIDE:
    # PySide6 uses Signal instead of pyqtSignal
    QtCore.pyqtSignal = QtCore.Signal
    QtCore.pyqtSlot = QtCore.Slot

import ida_kernwin


def is_headless_ida():
    """Detect if we're running in headless IDA (batch mode)"""

    return ida_kernwin.cvar.batch

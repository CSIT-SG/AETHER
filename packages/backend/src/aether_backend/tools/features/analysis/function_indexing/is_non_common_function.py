COMMON_LIBC_NAMES = {
    "memcpy",
    "memset",
    "memmove",
    "memcmp",
    "strlen",
    "strcpy",
    "strncpy",
    "strcmp",
    "strncmp",
    "strcat",
    "strncat",
    "strchr",
    "strrchr",
    "strstr",
    "strtol",
    "strtoul",
    "strtod",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "printf",
    "sprintf",
    "snprintf",
    "fprintf",
    "vprintf",
    "vsnprintf",
    "scanf",
    "sscanf",
    "fscanf",
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "fseek",
    "ftell",
    "fflush",
    "exit",
    "abort",
    "_exit",
    "atexit",
    "abs",
    "labs",
    "atoi",
    "atol",
    "atof",
    "qsort",
    "bsearch",
    "isdigit",
    "isalpha",
    "isalnum",
    "isspace",
    "toupper",
    "tolower",
    "time",
    "clock",
    "difftime",
    "mktime",
    "rand",
    "srand",
    "setjmp",
    "longjmp",
}

UNDERSCORE_WHITELIST = {
    "_DllMain",
    "_main",
    "_WinMain",
    "_wmain",
    "_DllEntryPoint",
    "_wWinMain",
    "_tmain",
}


def is_non_common_function(
    name: str, is_lib: bool, is_thunk: bool, size: int, min_size: int = 16
) -> bool:
    """Return True if *name* looks like a real function worth analyzing."""
    if not name:
        return False

    if is_lib or is_thunk:
        return False

    if size > 0 and size < min_size:
        return False

    if name in COMMON_LIBC_NAMES:
        return False

    if name.startswith("_") and name not in UNDERSCORE_WHITELIST:
        if name.startswith("__") or name.startswith("___"):
            return False
        bare = name.lstrip("_")
        if bare in COMMON_LIBC_NAMES:
            return False

    return True

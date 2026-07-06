import re

_IDA_REGEX = "sub|nullsub|j|loc|locret|off|seg|byte|word|dword|qword|byte3|flt|dbl|tbyte|packreal|xmmword|ymmword|zmmword|asc|stru|custdata|algn|unk|arg|var"

_VALID_INPUT = re.compile(
    rf"""
    ^
        (?:0x|0X|(?:{_IDA_REGEX})_)?  # Optional prefix
        (?P<addr>[0-9a-f]+)         # Hexadecimal address
    $
    """,
    re.VERBOSE | re.IGNORECASE,
)

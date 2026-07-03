import re

_IDA_REGEX = "sub|nullsub|j|loc|locret|off|seg|byte|word|dword|qword|byte3|flt|dbl|tbyte|packreal|xmmword|ymmword|zmmword|asc|stru|custdata|algn|unk|arg|var"

_VALID_INPUT = re.compile(
    fr"""
    ^
    (?:
        0x|0X|(?:{_IDA_REGEX})_       # named 'prefix'
        (?P<prefixed_hex>[0-9a-f]+)   # named 'prefixed_hex'
      |                                # OR
        (?P<unprefixed_hex>[0-9a-f]*[a-f][0-9a-f]*)   # named 'unprefixed_hex'
    )
    $
    """,
    re.VERBOSE | re.IGNORECASE,
)

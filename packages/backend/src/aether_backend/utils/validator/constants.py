import re

IDA_REGEX = "sub_|nullsub_|j_|loc_|locret_|off_|seg_|byte_|word_|dword_|qword_|byte3_|flt_|dbl_|tbyte_|packreal_|xmmword_|ymmword_|zmmword_|asc_|stru_|custdata_|algn_|unk_|arg_|var_"

_VALID_INPUT = re.compile(
    r"""
    ^
    (?:
        (?:0x|0X|{IDA_REGEX})      # named 'prefix'
        (?P<prefixed_hex>[0-9a-f]+)   # named 'prefixed_hex'
      |                                # OR
        (?P<unprefixed_hex>[0-9a-f]*[a-f][0-9a-f]*)   # named 'unprefixed_hex'
    )
    $
    """,
    re.VERBOSE | re.IGNORECASE,
)

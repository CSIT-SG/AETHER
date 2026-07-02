from collections import defaultdict

import ida_hexrays

# Used to map statement opcode to correct comment anchor position
# Documentation for the opcode values can be found at https://python.docs.hex-rays.com/ida_hexrays/index.html
# Documentation for the comment anchors can be found at https://python.docs.hex-rays.com/namespaceida__hexrays.html
# This is needed because comments in IDA require certain anchor positions and thats based on the opcode
# Otherwise, the comment will become an orphan comment
OP_TO_ITP: defaultdict[int, int] = defaultdict(
    lambda: ida_hexrays.ITP_SEMI,
    {
        ida_hexrays.cit_if: ida_hexrays.ITP_BLOCK1,
        ida_hexrays.cit_while: ida_hexrays.ITP_BLOCK1,
        ida_hexrays.cit_for: ida_hexrays.ITP_BLOCK1,
        ida_hexrays.cit_do: ida_hexrays.ITP_BLOCK1,
        ida_hexrays.cit_switch: ida_hexrays.ITP_BLOCK1,
        ida_hexrays.cit_block: ida_hexrays.ITP_BRACE1,
        ida_hexrays.cit_return: ida_hexrays.ITP_SEMI,
        ida_hexrays.cit_expr: ida_hexrays.ITP_SEMI,
    },
)

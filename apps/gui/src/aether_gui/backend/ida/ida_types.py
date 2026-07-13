from typing import TypedDict


class IDAContext(TypedDict):
    """Enum used to extract and parse IDA Context to LLM and MCP server"""

    current_ea: int | None
    function_ea: int | None
    function_name: str | None
    pseudocode: str | None
    disassembly: str | None
    selected_text: str | None
    processor: str | None
    bits: int | None
    input_file_path: str | None

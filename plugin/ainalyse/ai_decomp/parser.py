import re
from typing import Dict


def parse_ai_decomp_response_by_address(response_text: str) -> Dict[str, str]:
    """Parse AI decompilation response and extract function decompilations by address."""
    decompilations = {}
    
    # Pattern to match function blocks with more flexible formatting:
    # 1. ```0xADDRESS followed by content until ``` or end
    # 2. ```\n0xADDRESS followed by content until ``` or end
    pattern = re.compile(r'```\s*\n?\s*(0x[0-9a-fA-F]+)\s*\n(.*?)(?:\n```|$)', re.DOTALL)
    
    for match in pattern.finditer(response_text):
        func_addr = match.group(1)  # The address like 0xa121ae
        decomp_code = match.group(2).strip()
        
        if decomp_code and func_addr:
            # Always overwrite - this handles chunking where we get partial then complete functions
            decompilations[func_addr] = decomp_code
    
    return decompilations

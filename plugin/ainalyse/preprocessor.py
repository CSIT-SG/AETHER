import re
from typing import Dict


def strip_and_reformat_pseudocode_for_ai_decomp(pseudocode: str) -> str:
    """
    Clean pseudocode for AI decompilation by removing address prefixes, comments,
    and IDA-specific annotations, returning only clean code.
    """
    lines = pseudocode.splitlines()
    result = []
    line_re = re.compile(r'^\s*/\*\s*line:\s*(\d+)(?:,\s*address:\s*(0x[0-9a-fA-F]+))?\s*\*/\s*(.*)$')
    # Regex to match end-of-line comments with square brackets like: // [rsp+3Fh] [rbp-21h]
    eol_comment_re = re.compile(r'\s*//\s*\[[^\]]+\].*$')
    
    for line in lines:
        # Skip lines that have our internal formatting prefixes
        if line.strip().startswith('cannotComment;'):
            # Extract just the code part after cannotComment;
            clean_line = line.split('cannotComment;', 1)[1].strip()
            if clean_line:
                # Strip end-of-line comments with square brackets
                clean_line = eol_comment_re.sub('', clean_line).rstrip()
                if clean_line:
                    result.append(clean_line)
            continue
        elif re.match(r'^\s*0x[0-9a-fA-F]+;', line):
            # Extract just the code part after address;
            clean_line = re.sub(r'^\s*0x[0-9a-fA-F]+;\s*', '', line)
            if clean_line:
                # Strip end-of-line comments with square brackets
                clean_line = eol_comment_re.sub('', clean_line).rstrip()
                if clean_line:
                    result.append(clean_line)
            continue
            
        m = line_re.match(line)
        if m:
            code = m.group(3)
            if code:
                # Strip end-of-line comments with square brackets
                code = eol_comment_re.sub('', code).rstrip()
                if code:
                    result.append(code)
        else:
            # Regular line without our special formatting
            if line.strip():
                # Strip end-of-line comments with square brackets
                clean_line = eol_comment_re.sub('', line).rstrip()
                if clean_line.strip():
                    result.append(clean_line)
            else:
                result.append("")  # Preserve empty lines
    
    return "\n".join(result)

def format_pseudocode_listing_for_ai_decomp(pseudocode_store: Dict[str, str], function_address_map: Dict[str, str]) -> str:
    """Format pseudocode listing for AI decompilation without address prefixes, but include function addresses in headers."""
    if not pseudocode_store:
        return "FUNCTIONS PSEUDOCODE:\n\nNo pseudocode collected yet."
    listing = "FUNCTIONS PSEUDOCODE:\n"
    for func_name, code in pseudocode_store.items():
        # Use the clean formatting for AI decompilation
        formatted_code = strip_and_reformat_pseudocode_for_ai_decomp(code)
        # Get the function address for this function
        func_addr = function_address_map.get(func_name, "unknown")
        listing += f"\n=====\n{func_name}(...) [{func_addr}]\n=====\n\n{formatted_code.strip()}\n"
    return listing

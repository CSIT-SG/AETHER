"""
Code extractor node that extracts and cleans C code from LLM reasoning responses.
Handles escaped characters and formats code properly before assessment.
"""

import re


def extract_and_clean_code(response) -> str:
    """
    Extract C code block from LLM response and clean it properly.
    
    This function:
    1. Extracts code from markdown code blocks
    2. Handles escaped newlines (\\n) and converts them to actual newlines
    3. Removes extra whitespace while preserving code structure
    4. Returns clean, compilable C code
    
    Args:
        response: The full LLM response with reasoning and code (string or message object)
    
    Returns:
        Clean C code ready for assessment and compilation
    """
    
    if hasattr(response, 'content'):
        response = response.content
    
    if not isinstance(response, str):
        response = str(response)
    
    code_block_pattern = r'```[cC]\n[\s\S]*?```'
    matches = re.findall(code_block_pattern, response, re.DOTALL)
    
    raw_code = None
    if matches:
        # Use the last code block (usually the final deobfuscated version)
        raw_code = matches[-1].strip()
    else:
        # Fallback: Try to find function definitions directly
        function_pattern = r'((?:int|void|char|unsigned|static|inline|const|__fastcall)\s+\w+\s*\([^)]*\)\s*\{[\s\S]*?\n\})'
        func_matches = re.findall(function_pattern, response, re.MULTILINE)
        
        if func_matches:
            raw_code = func_matches[-1].strip()
        else:
            # Return original response if no code found
            raw_code = response.strip()
    
    # Clean the extracted code
    cleaned_code = clean_c_code(raw_code)
    return cleaned_code


def clean_c_code(code: str) -> str:
    """
    Clean C code by handling escaped characters and formatting.
    
    Args:
        code: Raw C code that may contain escaped newlines and other issues
    
    Returns:
        Cleaned C code with proper formatting
    """
    
    # Handle literal escaped newlines (\\n) - convert to actual newlines
    
    string_literals = []
    def save_string(match):
        string_literals.append(match.group(0))
        return f'__STRING_PLACEHOLDER_{len(string_literals) - 1}__'
    
    # Match string literals (both single and double quoted)
    code = re.sub(r'"(?:[^"\\]|\\.)*"', save_string, code)
    code = re.sub(r"'(?:[^'\\]|\\.)*'", save_string, code)
    
    # Now convert escaped newlines to actual newlines (outside of strings)
    # Handle both \\n and \n patterns
    code = code.replace('\\n', '\n')
    
    # Handle other common escaped characters that might appear
    code = code.replace('\\t', '\t')
    code = code.replace('\\r', '')
    
    # Restore string literals
    for i, literal in enumerate(string_literals):
        code = code.replace(f'__STRING_PLACEHOLDER_{i}__', literal)
    
    # Remove excessive blank lines (more than 2 consecutive)
    code = re.sub(r'\n{3,}', '\n\n', code)
    
    # Remove trailing whitespace from each line
    lines = code.split('\n')
    lines = [line.rstrip() for line in lines]
    code = '\n'.join(lines)
    
    # Ensure consistent indentation (remove leading/trailing whitespace from entire block)
    code = code.strip()
    
    return code

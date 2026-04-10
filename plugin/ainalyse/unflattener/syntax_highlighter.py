import re

import ida_lines


class CSyntaxHighlighter:
    """C/C++ syntax highlighter that closely follows the hilite.html implementation."""
    
    def __init__(self):
        # Keywords from hilite.html
        self.keywords = [
            'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do',
            'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if',
            'inline', 'int', 'long', 'register', 'restrict', 'return', 'short',
            'signed', 'sizeof', 'static', 'struct', 'switch', 'typedef', 'union',
            'unsigned', 'void', 'volatile', 'while', '_Bool', '_Complex', '_Imaginary'
        ]
        
        # Types from hilite.html - expanded to include IDA-specific types
        self.types = [
            'int', 'char', 'float', 'double', 'void', 'short', 'long', 'signed',
            'unsigned', 'const', 'volatile', 'static', 'extern', 'auto', 'register',
            'struct', 'union', 'enum', 'typedef', 'size_t', 'ptrdiff_t', 'wchar_t',
            'FILE', 'NULL', 'bool', 'true', 'false', 'char *',
            # IDA-specific types
            '__int8', '__int16', '__int32', '__int64', '__fastcall', '__cdecl', '__stdcall',
            '__thiscall', '__vectorcall', '_BYTE', '_WORD', '_DWORD', '_QWORD'
        ]
        
        # Remove constants - we won't highlight them separately
        self.constants = []
        
        # Add variable tracking
        self.declared_variables = set()
        
        # Don't filter types - this was causing problems with highlighting
        # self.types = list(set(self.types) - set(self.keywords))
        
        # Make sure these critical types are included 
        self.types.extend(['__int64', 'unsigned int', '__int8', 'unsigned __int8', 
                         'unsigned char', 'signed int', 'signed char'])
        
        # Add debugging flag
        self.debug_highlighting = True
        
        # Add think block tracking
        self.in_think_block = False
    
    def escape_html_entities(self, text):
        """Escape HTML entities like hilite.html does with escapeHtml."""
        # IDA already handles this, but we need to be aware of it
        return text
    
    def protect_content(self, content, protected_content, protected_index):
        """Protect content from further processing, like hilite.html."""
        placeholder = f"__PROTECTED_{protected_index[0]}__"
        protected_content.append(content)
        protected_index[0] += 1
        return placeholder
    
    def restore_content(self, text, protected_content):
        """Restore protected content, like hilite.html."""
        for i in range(len(protected_content) - 1, -1, -1):
            text = text.replace(f"__PROTECTED_{i}__", protected_content[i])
        return text
    
    def parse_variable_declarations(self, code_line: str):
        """Extract variable names from declarations and add to tracking set."""
        # Skip comments and preprocessor
        if code_line.strip().startswith('#'):
            return
            
        # Skip if the line is already detected as a comment
        if code_line.strip().startswith('//') or code_line.strip().startswith('/*'):
            return
            
        # IDA-style variable declaration patterns
        patterns = [
            # Basic type var;
            r'\b(?:' + '|'.join(re.escape(t) for t in self.types) + r')\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[;,]',
            # Type with pointer/reference
            r'\b(?:' + '|'.join(re.escape(t) for t in self.types) + r')\s*[\*&]+\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[;,]',
            # IDA-style local variable declaration
            r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*;',
            # Function parameter
            r'^\s*(?:' + '|'.join(re.escape(t) for t in self.types) + r')\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\)',
            # IDA local var in function args
            r'\(\s*(?:' + '|'.join(re.escape(t) for t in self.types) + r')\s+([a-zA-Z_][a-zA-Z0-9_]*)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, code_line)
            for match in matches:
                if match and match not in self.keywords and match not in self.types:
                    self.declared_variables.add(match)
                    print(f"[DEBUG] Found variable declaration: {match}")
    
    def highlight_multiline_comment_lines(self, text: str) -> str:
        """Handle multiline comments by adding AUTOCMT to each line within the comment."""
        if '/*' not in text:
            return text
            
        # Preserve original line breaks
        lines = text.split('\n')
        in_comment = False
        result_lines = []
        
        for i, line in enumerate(lines):
            # Check if this line starts or continues a multiline comment
            if in_comment:
                # Line is inside a comment
                if '*/' in line:
                    # Comment ends on this line
                    parts = line.split('*/', 1)
                    comment_part = parts[0] + '*/'
                    rest_part = parts[1] if len(parts) > 1 else ''
                    
                    # Color the comment part
                    colored_comment = (ida_lines.SCOLOR_ON + ida_lines.SCOLOR_AUTOCMT + 
                                     comment_part + 
                                     ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_AUTOCMT)
                    
                    # Add the colored comment and the rest of the line
                    result_lines.append(colored_comment + rest_part)
                    in_comment = False
                else:
                    # Entire line is part of comment
                    colored_line = (ida_lines.SCOLOR_ON + ida_lines.SCOLOR_AUTOCMT + 
                                  line + 
                                  ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_AUTOCMT)
                    result_lines.append(colored_line)
            else:
                # Check if a comment starts on this line
                if '/*' in line:
                    if '*/' in line and line.find('/*') < line.find('*/'):
                        # Single line comment /* ... */
                        before, rest = line.split('/*', 1)
                        comment, after = rest.split('*/', 1)
                        comment = '/*' + comment + '*/'
                        
                        colored_comment = (ida_lines.SCOLOR_ON + ida_lines.SCOLOR_AUTOCMT + 
                                         comment + 
                                         ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_AUTOCMT)
                        
                        result_lines.append(before + colored_comment + after)
                    else:
                        # Start of multiline comment
                        before, comment = line.split('/*', 1)
                        comment = '/*' + comment
                        
                        colored_comment = (ida_lines.SCOLOR_ON + ida_lines.SCOLOR_AUTOCMT + 
                                         comment + 
                                         ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_AUTOCMT)
                        
                        result_lines.append(before + colored_comment)
                        in_comment = True
                else:
                    # Normal line
                    result_lines.append(line)
        
        return '\n'.join(result_lines)

    def highlight_line(self, code_line: str) -> str:
        """
        Apply C/C++ syntax highlighting to a single line following hilite.html logic.
        """
        if not code_line.strip():
            return code_line
        
        # Check for think block markers first
        if "START_THINK" in code_line:
            self.in_think_block = True
            # Apply SCOLOR_NUMBER to the entire line
            return (ida_lines.SCOLOR_ON + ida_lines.SCOLOR_NUMBER + 
                   code_line + 
                   ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_NUMBER)
        
        if "END_THINK" in code_line:
            # Apply SCOLOR_NUMBER to this line too, then reset state
            colored_line = (ida_lines.SCOLOR_ON + ida_lines.SCOLOR_NUMBER + 
                           code_line + 
                           ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_NUMBER)
            self.in_think_block = False
            return colored_line
        
        # If we're inside a think block, color the entire line with SCOLOR_NUMBER
        if self.in_think_block:
            return (ida_lines.SCOLOR_ON + ida_lines.SCOLOR_NUMBER + 
                   code_line + 
                   ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_NUMBER)
        
        # Check if line is already part of a colored multiline comment
        if ida_lines.SCOLOR_AUTOCMT in code_line:
            return code_line
            
        # Parse variable declarations first
        self.parse_variable_declarations(code_line)
        
        # Start with the original line (escaped)
        highlighted = self.escape_html_entities(code_line)
        
        # Protected content system like hilite.html
        protected_content = []
        protected_index = [0]  # Use list for reference passing
        
        # 1. Handle single-line comments first
        def protect_comment(match):
            comment_text = match.group(0)
            colored_comment = ida_lines.SCOLOR_ON + ida_lines.SCOLOR_AUTOCMT + comment_text + ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_AUTOCMT
            return self.protect_content(colored_comment, protected_content, protected_index)
        
        highlighted = re.sub(r'//.*$', protect_comment, highlighted)
        
        # 2. Handle preprocessor directives
        if highlighted.strip().startswith('#'):
            # Use SCOLOR_MACRO for preprocessor (matches IDA's pink/magenta)
            colored_line = (ida_lines.SCOLOR_ON + ida_lines.SCOLOR_MACRO + 
                           highlighted + 
                           ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_MACRO)
            return self.restore_content(colored_line, protected_content)
        
        # 3. Highlight string literals and protect them
        def protect_string(match):
            string_text = match.group(0)
            # Use SCOLOR_NUMBER for string literals (orange/yellow)
            colored_string = (ida_lines.SCOLOR_ON + ida_lines.SCOLOR_NUMBER + 
                            string_text + 
                            ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_NUMBER)
            return self.protect_content(colored_string, protected_content, protected_index)
        
        highlighted = re.sub(r'"(?:[^"\\]|\\.)*"', protect_string, highlighted)
        
        # 4. Highlight character literals and protect them
        def protect_char(match):
            char_text = match.group(0)
            # Use SCOLOR_NUMBER for character literals (same as strings)
            colored_char = (ida_lines.SCOLOR_ON + ida_lines.SCOLOR_NUMBER + 
                          char_text + 
                          ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_NUMBER)
            return self.protect_content(colored_char, protected_content, protected_index)
        
        highlighted = re.sub(r"'(?:[^'\\]|\\.)*'", protect_char, highlighted)
        
        # 5. Highlight numbers and protect them (following hilite.html pattern)
        def protect_number(match):
            number_text = match.group(0)
            # Use SCOLOR_KEYWORD for numbers (black/dark)
            colored_number = (ida_lines.SCOLOR_ON + ida_lines.SCOLOR_KEYWORD + 
                            number_text + 
                            ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_KEYWORD)
            return self.protect_content(colored_number, protected_content, protected_index)
        
        # Hex, octal, and decimal numbers like hilite.html
        highlighted = re.sub(r'\b(?:0[xX][0-9a-fA-F]+|0[0-7]+|\d+\.?\d*[fFlL]?)\b', 
                           protect_number, highlighted)
        
        # 6. Highlight types first - Move up in priority!
        def protect_type(match):
            type_text = match.group(0)
            if self.debug_highlighting:
                print(f"[DEBUG] Highlighting type: {type_text}")
            colored_type = ida_lines.SCOLOR_ON + ida_lines.SCOLOR_AUTOCMT + type_text + ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_AUTOCMT
            return self.protect_content(colored_type, protected_content, protected_index)
        
        # Special check for unsigned int which needs special handling
        if "unsigned int" in highlighted:
            highlighted = highlighted.replace("unsigned int", 
                ida_lines.SCOLOR_ON + ida_lines.SCOLOR_AUTOCMT + "unsigned int" + 
                ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_AUTOCMT)
        
        # Special check for unsigned __int8/16/32/64
        for special_type in ["unsigned __int8", "unsigned __int16", "unsigned __int32", "unsigned __int64"]:
            if special_type in highlighted:
                highlighted = highlighted.replace(special_type, 
                    ida_lines.SCOLOR_ON + ida_lines.SCOLOR_AUTOCMT + special_type + 
                    ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_AUTOCMT)
        
        # Use word boundary for each type to avoid partial matches
        for type_name in self.types:
            pattern = r'\b' + re.escape(type_name) + r'\b'
            highlighted = re.sub(pattern, protect_type, highlighted)
        
        # Special handling for common type combinations
        compound_types = [
            r'\bunsigned\s+int\b', 
            r'\bunsigned\s+char\b',
            r'\bsigned\s+int\b',
            r'\bsigned\s+char\b',
            r'\blong\s+int\b',
            r'\bshort\s+int\b'
        ]
        
        for type_pattern in compound_types:
            def protect_compound_type(match):
                type_text = match.group(0)
                print(f"[DEBUG] Highlighting compound type: {type_text}")
                colored_type = ida_lines.SCOLOR_ON + ida_lines.SCOLOR_AUTOCMT + type_text + ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_AUTOCMT
                return self.protect_content(colored_type, protected_content, protected_index)
                
            highlighted = re.sub(type_pattern, protect_compound_type, highlighted)
        
        # Highlight declared variables with AUTOCMT color (changed from CODNAME)
        def protect_variable(match):
            var_name = match.group(0)
            colored_var = ida_lines.SCOLOR_ON + chr(24) + var_name + ida_lines.SCOLOR_OFF + chr(24)
            return self.protect_content(colored_var, protected_content, protected_index)
        
        # Special handling for function parameters
        for var_name in self.declared_variables:
            pattern = r'\b' + re.escape(var_name) + r'\b'
            highlighted = re.sub(pattern, protect_variable, highlighted)
        
        # 8. Highlight keywords and protect them
        def protect_keyword(match):
            keyword_text = match.group(0)
            colored_keyword = ida_lines.SCOLOR_ON + ida_lines.SCOLOR_KEYWORD + keyword_text + ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_KEYWORD
            return self.protect_content(colored_keyword, protected_content, protected_index)
        
        for keyword in self.keywords:
            pattern = r'\b' + re.escape(keyword) + r'\b'
            highlighted = re.sub(pattern, protect_keyword, highlighted)
        
        # 9. Highlight function calls with default blue color
        def protect_function(match):
            func_name = match.group(1)
            paren = match.group(2)
            # Skip if it's already been highlighted as a keyword or type
            if func_name in self.keywords or func_name in self.types:
                return match.group(0)
            
            colored_func = ida_lines.SCOLOR_ON + ida_lines.SCOLOR_DEFAULT + func_name + ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_DEFAULT
            return self.protect_content(colored_func + paren, protected_content, protected_index)
        
        highlighted = re.sub(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(\()', protect_function, highlighted)
        
        # 10-11. Highlight operators
        def protect_operator(match):
            op_text = match.group(0)
            # Use SCOLOR_KEYWORD for operators (black/dark)
            colored_op = (ida_lines.SCOLOR_ON + ida_lines.SCOLOR_KEYWORD + 
                        op_text + 
                        ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_KEYWORD)
            return self.protect_content(colored_op, protected_content, protected_index)
        
        # Multi-character operators first (like hilite.html)
        multi_char_ops = [r'\+\+', r'--', r'\+=', r'-=', r'\*=', r'/=', r'%=', r'\|=', r'\^=',
                         r'==', r'!=', r'<=', r'>=', r'<<', r'>>', r'&&', r'\|\|', r'->', r'\.\.\.' ]
        
        for op in multi_char_ops:
            highlighted = re.sub(op, protect_operator, highlighted)
        
        # Single-character operators
        single_char_ops = [r'\+', r'-', r'\*', r'/', r'%', r'\|', r'\^', r'~', r'!', 
                          r'=', r'\?', r':', r'<', r'>']
        
        for op in single_char_ops:
            highlighted = re.sub(op, protect_operator, highlighted)
        
        # 12. Don't highlight brackets and parentheses to match IDA's style
        # IDA uses default color for these symbols
        
        # Restore all protected content
        highlighted = self.restore_content(highlighted, protected_content)
        
        return highlighted

# Global highlighter instance
_highlighter = CSyntaxHighlighter()

def highlight_c_code(code_line: str) -> str:
    """
    Apply C/C++ syntax highlighting to a single line of code using IDA's color tags.
    This follows the hilite.html implementation closely and matches IDA's native colors.
    """
    return _highlighter.highlight_line(code_line)

def highlight_c_code_multiline(code_text: str) -> str:
    """
    Apply C/C++ syntax highlighting to multiline code, handling multiline comments properly.
    """
    # First process all the code to find variable declarations
    lines = code_text.split('\n')
    for line in lines:
        _highlighter.parse_variable_declarations(line)
    
    print(f"[DEBUG] Found variables: {_highlighter.declared_variables}")
    
    # Then handle multiline comments across the entire text
    highlighted_text = _highlighter.highlight_multiline_comment_lines(code_text)
    
    # Then process each line for other syntax elements
    lines = highlighted_text.split('\n')
    result_lines = []
    
    for line in lines:
        # Skip lines that are already completely colored as comments
        if line.startswith(ida_lines.SCOLOR_ON + ida_lines.SCOLOR_AUTOCMT) and line.endswith(ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_AUTOCMT):
            result_lines.append(line)
        else:
            result_lines.append(_highlighter.highlight_line(line))
    
    return '\n'.join(result_lines)

def debug_ida_colors():
    """Debug function to print all IDA color codes from 1-32."""
    print("\n===== IDA COLOR CODE DEBUG =====")
    
    # Create a test string
    test_text = "This is a test string for color code"
    
    # Test raw color codes 1-32
    for i in range(1, 33):
        try:
            # Convert number to character
            color_char = chr(i)
            
            # Try to create a colored string
            colored_text = ida_lines.SCOLOR_ON + color_char + test_text + ida_lines.SCOLOR_OFF + color_char
            
            # Print the result
            print(f"Color code {i:02d} (char: {repr(color_char)}): {colored_text}")
        except Exception as e:
            print(f"Color code {i:02d}: ERROR - {str(e)}")
    
    # Test known color constants
    print("\n===== IDA COLOR CONSTANTS =====")
    color_constants = [
        'SCOLOR_DEFAULT', 'SCOLOR_REGCMT', 'SCOLOR_RPTCMT', 'SCOLOR_AUTOCMT',
        'SCOLOR_INSN', 'SCOLOR_DATNAME', 'SCOLOR_DNAME', 'SCOLOR_DEMNAME',
        'SCOLOR_SYMBOL', 'SCOLOR_CHAR', 'SCOLOR_STRING', 'SCOLOR_NUMBER',
        'SCOLOR_VOIDOP', 'SCOLOR_CREF', 'SCOLOR_DREF', 'SCOLOR_CREFTAIL',
        'SCOLOR_DREFTAIL', 'SCOLOR_KEYWORD', 'SCOLOR_REG', 'SCOLOR_IMPNAME',
        'SCOLOR_SEGNAME', 'SCOLOR_UNKNAME', 'SCOLOR_CNAME', 'SCOLOR_UNAME',
        'SCOLOR_COLLAPSED', 'SCOLOR_ADDR', 'SCOLOR_ALTOP', 'SCOLOR_HIDNAME',
        'SCOLOR_LIBNAME', 'SCOLOR_LOCNAME', 'SCOLOR_CODNAME', 'SCOLOR_ASMDIR',
        'SCOLOR_MACRO', 'SCOLOR_DSTR', 'SCOLOR_DCHAR', 'SCOLOR_DNUM',
        'SCOLOR_KEYWORD1', 'SCOLOR_KEYWORD2', 'SCOLOR_KEYWORD3', 'SCOLOR_ERROR',
        'SCOLOR_OPND1', 'SCOLOR_OPND2', 'SCOLOR_OPND3', 'SCOLOR_OPND4', 'SCOLOR_OPND5',
        'SCOLOR_OPND6', 'SCOLOR_BINPREF', 'SCOLOR_EXTRA', 'SCOLOR_ALTOP'
    ]
    
    for const_name in color_constants:
        try:
            if hasattr(ida_lines, const_name):
                color_value = getattr(ida_lines, const_name)
                colored_text = ida_lines.SCOLOR_ON + color_value + test_text + ida_lines.SCOLOR_OFF + color_value
                print(f"{const_name} = {repr(color_value)}: {colored_text}")
            else:
                print(f"{const_name}: Not found in ida_lines")
        except Exception as e:
            print(f"{const_name}: ERROR - {str(e)}")
    
    print("===== END COLOR DEBUG =====")

# Run the debug function when the module is loaded
debug_ida_colors()

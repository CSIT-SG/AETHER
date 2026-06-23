from __future__ import annotations

import ast
from enum import StrEnum
from typing import Any

from .bridge import ChatbotBackendBridge, IDAChatbotBackendBridge


class StructToolNames(StrEnum):
    STRUCT_CREATE = "struct_create"
    STRUCT_GET_DEFINITION = "struct_get_definition"
    STRUCT_LIST = "struct_list"
    STRUCT_RESOLVE_OFFSET_EXPR = "struct_resolve_offset_expr"
    STRUCT_GET_NEXT_OFFSET = "struct_get_next_offset"
    STRUCT_ADD_FIELD = "struct_add_field"
    STRUCT_UPDATE_FIELD = "struct_update_field"
    STRUCT_REMOVE_FIELD = "struct_remove_field"
    STRUCT_APPLY_TO_VARIABLE_OR_ADDRESS = "struct_apply_to_variable_or_address"
    STRUCT_RENAME = "struct_rename"
    STRUCT_SET_SIZE = "struct_set_size"
    STRUCT_REQUEST_MORE_CONTEXT = "struct_request_more_context"
    GET_FUNCTION_PSEUDOCODE = "get_function_pseudocode"
    GET_DATA_AT_ADDRESS = "get_data_at_address"
    GET_XREFS_TO = "get_xrefs_to"


STRUCT_TOOL_SPECS = {
    StructToolNames.STRUCT_CREATE: {
        "description": "Create a struct in IDA local types.",
        "parameters": {
            "type": "object",
            "properties": {
                "struct_name": {"type": "string"},
                "size": {"type": "string"},
            },
            "required": ["struct_name"],
        },
        "arg_order": ["struct_name", "size"],
    },
    StructToolNames.STRUCT_GET_DEFINITION: {
        "description": "Get current struct fields with names/types/offsets.",
        "parameters": {
            "type": "object",
            "properties": {"struct_name": {"type": "string"}},
            "required": ["struct_name"],
        },
        "arg_order": ["struct_name"],
    },
    StructToolNames.STRUCT_LIST: {
        "description": "List available structs in local types.",
        "parameters": {"type": "object", "properties": {}},
        "arg_order": [],
    },
    StructToolNames.STRUCT_RESOLVE_OFFSET_EXPR: {
        "description": "Resolve a struct offset arithmetic expression safely.",
        "parameters": {
            "type": "object",
            "properties": {
                "struct_name": {"type": "string"},
                "offset_expr": {"type": "string"},
            },
            "required": ["struct_name", "offset_expr"],
        },
        "arg_order": ["struct_name", "offset_expr"],
    },
    StructToolNames.STRUCT_GET_NEXT_OFFSET: {
        "description": "Compute the next safe field offset based on existing struct fields.",
        "parameters": {
            "type": "object",
            "properties": {
                "struct_name": {"type": "string"},
                "alignment": {"type": "string"},
            },
            "required": ["struct_name"],
        },
        "arg_order": ["struct_name", "alignment"],
    },
    StructToolNames.STRUCT_ADD_FIELD: {
        "description": "Add or replace a struct field by field name/type/offset expression.",
        "parameters": {
            "type": "object",
            "properties": {
                "struct_name": {"type": "string"},
                "field_name": {"type": "string"},
                "field_type": {"type": "string"},
                "offset_expr": {"type": "string"},
                "replace_existing": {"type": "string"},
            },
            "required": ["struct_name", "field_name", "field_type", "offset_expr"],
        },
        "arg_order": ["struct_name", "field_name", "field_type", "offset_expr", "replace_existing"],
    },
    StructToolNames.STRUCT_UPDATE_FIELD: {
        "description": "Update an existing struct field's name/type/offset.",
        "parameters": {
            "type": "object",
            "properties": {
                "struct_name": {"type": "string"},
                "field_name": {"type": "string"},
                "new_field_name": {"type": "string"},
                "new_field_type": {"type": "string"},
                "new_offset_expr": {"type": "string"},
            },
            "required": ["struct_name", "field_name"],
        },
        "arg_order": ["struct_name", "field_name", "new_field_name", "new_field_type", "new_offset_expr"],
    },
    StructToolNames.STRUCT_REMOVE_FIELD: {
        "description": "Remove a struct field by name or offset expression.",
        "parameters": {
            "type": "object",
            "properties": {
                "struct_name": {"type": "string"},
                "field_name": {"type": "string"},
                "offset_expr": {"type": "string"},
            },
            "required": ["struct_name"],
        },
        "arg_order": ["struct_name", "field_name", "offset_expr"],
    },
    StructToolNames.STRUCT_APPLY_TO_VARIABLE_OR_ADDRESS: {
        "description": "Apply struct type to a function variable (including arguments), a global variable, or a direct address.",
        "parameters": {
            "type": "object",
            "properties": {
                "struct_name": {"type": "string"},
                "function_name": {"type": "string"},
                "variable_name": {"type": "string"},
                "address": {"type": "string"},
            },
            "required": ["struct_name"],
        },
        "arg_order": ["struct_name", "function_name", "variable_name", "address"],
    },
    StructToolNames.STRUCT_RENAME: {
        "description": "Rename an existing struct to a new name.",
        "parameters": {
            "type": "object",
            "properties": {
                "old_name": {"type": "string"},
                "new_name": {"type": "string"},
            },
            "required": ["old_name", "new_name"],
        },
        "arg_order": ["old_name", "new_name"],
    },
    StructToolNames.STRUCT_SET_SIZE: {
        "description": "Set the explicit size of an existing struct in bytes.",
        "parameters": {
            "type": "object",
            "properties": {
                "struct_name": {"type": "string"},
                "size": {"type": "string"},
            },
            "required": ["struct_name", "size"],
        },
        "arg_order": ["struct_name", "size"],
    },
    StructToolNames.STRUCT_REQUEST_MORE_CONTEXT: {
        "description": "Ask the main agent for additional context before continuing struct work.",
        "parameters": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "question": {"type": "string"},
            },
            "required": ["request_id", "question"],
        },
        "arg_order": ["request_id", "question"],
    },
    StructToolNames.GET_FUNCTION_PSEUDOCODE: {
        "description": "Retrieve pseudocode for a function relevant to struct inference.",
        "parameters": {
            "type": "object",
            "properties": {"function_name": {"type": "string"}},
            "required": ["function_name"],
        },
        "arg_order": ["function_name"],
    },
    StructToolNames.GET_DATA_AT_ADDRESS: {
        "description": "Inspect bytes/string/disasm near an address for struct evidence.",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {"type": "string"},
                "count": {"type": "string"},
            },
            "required": ["location"],
        },
        "arg_order": ["location", "count"],
    },
    StructToolNames.GET_XREFS_TO: {
        "description": "Find xrefs to a function/address to understand struct usage flows.",
        "parameters": {
            "type": "object",
            "properties": {"location": {"type": "string"}},
            "required": ["location"],
        },
        "arg_order": ["location"],
    },
}


class StructToolbox:
    MAX_OFFSET = 0x7FFFFFFF

    def __init__(self, bridge: ChatbotBackendBridge | None = None):
        self.bridge = bridge or IDAChatbotBackendBridge()
        self.registry = {
            StructToolNames.STRUCT_CREATE: self.struct_create,
            StructToolNames.STRUCT_GET_DEFINITION: self.struct_get_definition,
            StructToolNames.STRUCT_LIST: self.struct_list,
            StructToolNames.STRUCT_RESOLVE_OFFSET_EXPR: self.struct_resolve_offset_expr,
            StructToolNames.STRUCT_GET_NEXT_OFFSET: self.struct_get_next_offset,
            StructToolNames.STRUCT_ADD_FIELD: self.struct_add_field,
            StructToolNames.STRUCT_UPDATE_FIELD: self.struct_update_field,
            StructToolNames.STRUCT_REMOVE_FIELD: self.struct_remove_field,
            StructToolNames.STRUCT_APPLY_TO_VARIABLE_OR_ADDRESS: self.struct_apply_to_variable_or_address,
            StructToolNames.STRUCT_RENAME: self.struct_rename,
            StructToolNames.STRUCT_SET_SIZE: self.struct_set_size,
            StructToolNames.STRUCT_REQUEST_MORE_CONTEXT: self.struct_request_more_context,
            StructToolNames.GET_FUNCTION_PSEUDOCODE: self.get_function_pseudocode,
            StructToolNames.GET_DATA_AT_ADDRESS: self.get_data_at_address,
            StructToolNames.GET_XREFS_TO: self.get_xrefs_to,
        }

    def execute(self, tool_name: str | StructToolNames, *args: str) -> str:
        normalized = StructToolNames(tool_name)
        return self.registry[normalized](*args)

    def execute_named(self, tool_name: str | StructToolNames, arguments: dict[str, object] | None = None) -> str:
        normalized = StructToolNames(tool_name)
        arguments = arguments or {}
        spec = STRUCT_TOOL_SPECS[normalized]
        args = ["" if arguments.get(name) is None else str(arguments.get(name)) for name in spec["arg_order"]]
        return self.execute(normalized, *args)

    def get_tool_definitions(self) -> list[dict[str, object]]:
        definitions = []
        for tool_name, spec in STRUCT_TOOL_SPECS.items():
            definitions.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool_name.value,
                        "description": spec["description"],
                        "parameters": spec["parameters"],
                    },
                }
            )
        return definitions

    def struct_create(self, struct_name: str, size: str = "") -> str:
        struct_name = struct_name.strip()
        if not struct_name:
            return "Error: struct_name is required."
        try:
            parsed_size = int(size, 0) if size else 0
        except ValueError:
            return f"Error: invalid size '{size}'."
        if parsed_size < 0:
            return "Error: size cannot be negative."
        return self.bridge.create_struct(struct_name, parsed_size)

    def struct_get_definition(self, struct_name: str) -> str:
        definition = self.bridge.get_struct_definition(struct_name.strip())
        if not definition:
            return f"Struct '{struct_name}' not found."
        size = int(definition.get("size", 0) or 0)
        lines = [f"Struct {definition.get('struct_name', struct_name)} (size={size} bytes, 0x{size:X}):"]
        fields = list(definition.get("fields", []))
        if not fields:
            lines.append("  <no fields>")
        for field in fields:
            lines.append(
                f"  - {field.get('field_name')} : {field.get('field_type')} @ 0x{int(field.get('offset', 0)):X}"
            )
        return "\n".join(lines)

    def struct_list(self) -> str:
        names = self.bridge.list_structs()
        return "\n".join(names) if names else "No structs found."

    def struct_resolve_offset_expr(self, struct_name: str, offset_expr: str) -> str:
        try:
            resolved = self._resolve_offset(struct_name.strip(), offset_expr.strip())
        except ValueError as exc:
            return f"Error: {exc}"
        return f"Resolved offset for '{struct_name}': {offset_expr} = {resolved} (0x{resolved:X})"

    def struct_get_next_offset(self, struct_name: str, alignment: str = "") -> str:
        definition = self.bridge.get_struct_definition(struct_name.strip())
        if not definition:
            return f"Struct '{struct_name}' not found."
        fields = definition.get("fields", [])
        next_offset = 0
        for field in fields:
            candidate = int(field.get("offset", 0))
            next_offset = max(next_offset, candidate + 1)
        try:
            align = int(alignment, 0) if alignment else 1
        except ValueError:
            return f"Error: invalid alignment '{alignment}'."
        if align <= 0:
            return "Error: alignment must be > 0."
        if next_offset % align != 0:
            next_offset += align - (next_offset % align)
        return f"Next suggested offset in '{struct_name}' is {next_offset} (0x{next_offset:X})"

    def struct_add_field(
        self,
        struct_name: str,
        field_name: str,
        field_type: str,
        offset_expr: str,
        replace_existing: str = "",
    ) -> str:
        if not field_name.strip():
            return "Error: field_name is required."
        if not field_type.strip():
            return "Error: field_type is required."
        try:
            offset = self._resolve_offset(struct_name.strip(), offset_expr.strip())
        except ValueError as exc:
            return f"Error: {exc}"
        replace = str(replace_existing or "").strip().lower() in {"1", "true", "yes", "y"}
        definition = self.bridge.get_struct_definition(struct_name.strip())
        if definition:
            existing = None
            for field in definition.get("fields", []):
                if int(field.get("offset", -1)) == int(offset):
                    existing = field
                    break
            if existing is not None:
                existing_name = str(existing.get("field_name") or "")
                existing_type = str(existing.get("field_type") or "")
                incoming_name = field_name.strip()
                incoming_type = field_type.strip()
                if existing_name == incoming_name and existing_type == incoming_type:
                    return (
                        f"No change: field '{incoming_name}' with type '{incoming_type}' "
                        f"already exists at offset 0x{int(offset):X} in '{struct_name.strip()}'."
                    )
                if not replace:
                    return (
                        "Error: offset collision detected. "
                        f"Offset 0x{int(offset):X} already has field '{existing_name}' ({existing_type}). "
                        "Use struct_update_field for meaningful edits, or set replace_existing=true "
                        "only when intentionally replacing the existing field."
                    )
        return self.bridge.add_struct_field(struct_name.strip(), field_name.strip(), field_type.strip(), offset)

    def struct_update_field(
        self,
        struct_name: str,
        field_name: str,
        new_field_name: str = "",
        new_field_type: str = "",
        new_offset_expr: str = "",
    ) -> str:
        new_offset = None
        if new_offset_expr.strip():
            try:
                new_offset = self._resolve_offset(struct_name.strip(), new_offset_expr.strip())
            except ValueError as exc:
                return f"Error: {exc}"
        return self.bridge.update_struct_field(
            struct_name.strip(),
            field_name.strip(),
            new_field_name.strip() or None,
            new_field_type.strip() or None,
            new_offset,
        )

    def struct_remove_field(self, struct_name: str, field_name: str = "", offset_expr: str = "") -> str:
        resolved_offset = None
        if offset_expr.strip():
            try:
                resolved_offset = self._resolve_offset(struct_name.strip(), offset_expr.strip())
            except ValueError as exc:
                return f"Error: {exc}"
        return self.bridge.remove_struct_field(
            struct_name.strip(),
            field_name.strip() or None,
            resolved_offset,
        )

    def struct_apply_to_variable_or_address(
        self,
        struct_name: str,
        function_name: str = "",
        variable_name: str = "",
        address: str = "",
    ) -> str:
        return self.bridge.apply_struct_to_variable_or_address(
            struct_name.strip(),
            function_name.strip() or None,
            variable_name.strip() or None,
            address.strip() or None,
        )

    def struct_rename(self, old_name: str, new_name: str) -> str:
        old_name = (old_name or "").strip()
        new_name = (new_name or "").strip()
        if not old_name:
            return "Error: old_name is required."
        if not new_name:
            return "Error: new_name is required."
        return self.bridge.rename_struct(old_name, new_name)

    def struct_set_size(self, struct_name: str, size: str) -> str:
        struct_name = (struct_name or "").strip()
        if not struct_name:
            return "Error: struct_name is required."
        try:
            parsed_size = int(str(size), 0)
        except ValueError:
            return f"Error: invalid size '{size}'."
        if parsed_size < 0:
            return "Error: size cannot be negative."
        return self.bridge.set_struct_size(struct_name, parsed_size)

    def struct_request_more_context(self, request_id: str, question: str) -> str:
        request_id = request_id.strip()
        question = question.strip()
        if not request_id:
            return "Error: request_id is required."
        if not question:
            return "Error: question is required."
        return f"[AGENT_QUERY] request_id={request_id} question={question}"

    def get_function_pseudocode(self, function_name: str) -> str:
        pseudocode = self.bridge.get_function_pseudocode(function_name)
        if pseudocode:
            return pseudocode
        return f"Function '{function_name}' not found."

    def get_data_at_address(self, location: str, count: str = "16") -> str:
        try:
            resolved = self.bridge.get_data_at_address(location, int(count))
        except ValueError:
            resolved = self.bridge.get_data_at_address(location, 16)
        if not resolved or "ea" not in resolved:
            return f"Error: Could not resolve address/name '{location}'."
        return (
            f"Data at {resolved['ea']} ({resolved.get('name') or 'unknown'}):\n"
            f"Hex: {resolved.get('bytes', 'No bytes found')}\n"
            f"String: {resolved.get('string', 'No string found')}\n"
            f"Disasm: {resolved.get('disasm') or 'N/A'}\n"
            f"Function context: {resolved.get('function_context', 'outside_function')}"
        )

    def get_xrefs_to(self, location: str) -> str:
        xrefs_found = self.bridge.get_xrefs_to(location) or []
        if not xrefs_found:
            return f"No cross-references found for '{location}'."
        target = xrefs_found[0].get("target", {}) if isinstance(xrefs_found[0], dict) else {}
        lines = []
        if target:
            lines.append(
                f"Target {target.get('name')} @ {target.get('ea')} [{target.get('context', 'outside_function')}]"
            )
        lines.append(f"Found {len(xrefs_found)} xref(s) to '{location}':")
        for xref in xrefs_found:
            if "from" not in xref:
                continue
            lines.append(f"  - {xref.get('from')} in {xref.get('name')} ({xref.get('type')})")
        return "\n".join(lines)

    def _resolve_offset(self, struct_name: str, offset_expr: str) -> int:
        if not offset_expr:
            raise ValueError("offset_expr cannot be empty")
        symbols: dict[str, int] = {}
        definition = self.bridge.get_struct_definition(struct_name)
        if definition:
            for field in definition.get("fields", []):
                name = str(field.get("field_name") or "").strip()
                if name:
                    symbols[name] = int(field.get("offset", 0))
        return _safe_eval_int_expr(offset_expr, symbols)


def _safe_eval_int_expr(expression: str, symbols: dict[str, int]) -> int:
    allowed_binops = {
        ast.Add: lambda a, b: a + b,
        ast.Sub: lambda a, b: a - b,
        ast.Mult: lambda a, b: a * b,
        ast.Div: lambda a, b: a // b,
        ast.FloorDiv: lambda a, b: a // b,
        ast.Mod: lambda a, b: a % b,
        ast.LShift: lambda a, b: a << b,
        ast.RShift: lambda a, b: a >> b,
        ast.BitAnd: lambda a, b: a & b,
        ast.BitOr: lambda a, b: a | b,
        ast.BitXor: lambda a, b: a ^ b,
    }
    allowed_unaryops = {
        ast.UAdd: lambda a: +a,
        ast.USub: lambda a: -a,
        ast.Invert: lambda a: ~a,
    }

    def _eval(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return int(node.value)
        if isinstance(node, ast.Name):
            if node.id not in symbols:
                raise ValueError(f"unknown offset symbol '{node.id}'")
            return int(symbols[node.id])
        if isinstance(node, ast.BinOp) and type(node.op) in allowed_binops:
            left = _eval(node.left)
            right = _eval(node.right)
            if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)) and right == 0:
                raise ValueError("division by zero")
            return int(allowed_binops[type(node.op)](left, right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in allowed_unaryops:
            return int(allowed_unaryops[type(node.op)](_eval(node.operand)))
        raise ValueError("unsupported expression")

    try:
        parsed = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"invalid offset expression '{expression}'") from exc
    result = _eval(parsed)
    if result < 0:
        raise ValueError("offset cannot be negative")
    if result > StructToolbox.MAX_OFFSET:
        raise ValueError(f"offset exceeds max supported value 0x{StructToolbox.MAX_OFFSET:X}")
    return int(result)


__all__ = ["StructToolNames", "STRUCT_TOOL_SPECS", "StructToolbox"]

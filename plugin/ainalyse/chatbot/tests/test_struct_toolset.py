import unittest

from ainalyse.chatbot.chatbot_ida.bridge import NullChatbotBackendBridge
from ainalyse.chatbot.chatbot_ida.struct_toolset import StructToolbox


class FakeStructBridge(NullChatbotBackendBridge):
    def __init__(self):
        self.structs = {
            "session_ctx": {
                "struct_name": "session_ctx",
                "fields": [
                    {"field_name": "hdr", "field_type": "uint32_t", "offset": 0},
                    {"field_name": "flags", "field_type": "uint16_t", "offset": 4},
                ],
            }
        }

    def list_structs(self):
        return sorted(self.structs.keys())

    def get_struct_definition(self, struct_name: str):
        return self.structs.get(struct_name)

    def create_struct(self, struct_name: str, size: int = 0, replace_if_exists: bool = False) -> str:
        if struct_name in self.structs and not replace_if_exists:
            return f"Struct '{struct_name}' already exists."
        self.structs[struct_name] = {"struct_name": struct_name, "fields": []}
        return f"Struct '{struct_name}' created."

    def add_struct_field(self, struct_name: str, field_name: str, field_type: str, offset: int) -> str:
        self.structs.setdefault(struct_name, {"struct_name": struct_name, "fields": []})
        self.structs[struct_name]["fields"].append(
            {"field_name": field_name, "field_type": field_type, "offset": int(offset)}
        )
        return f"Added/updated field '{field_name}' in '{struct_name}' at offset 0x{int(offset):X}."


class StructToolsetTests(unittest.TestCase):
    def test_offset_expression_supports_arithmetic_and_symbols(self):
        toolbox = StructToolbox(FakeStructBridge())
        output = toolbox.struct_resolve_offset_expr("session_ctx", "flags + 0x10")
        self.assertIn("20", output)
        self.assertIn("0x14", output)

    def test_add_field_uses_resolved_offset(self):
        bridge = FakeStructBridge()
        toolbox = StructToolbox(bridge)
        output = toolbox.struct_add_field("session_ctx", "token", "uint64_t", "flags + 8")
        self.assertIn("0xC", output)

    def test_negative_offsets_are_rejected(self):
        toolbox = StructToolbox(FakeStructBridge())
        output = toolbox.struct_resolve_offset_expr("session_ctx", "-1")
        self.assertTrue(output.startswith("Error:"))

    def test_empty_field_name_is_rejected(self):
        toolbox = StructToolbox(FakeStructBridge())
        output = toolbox.struct_add_field("session_ctx", "", "uint32_t", "0x10")
        self.assertEqual(output, "Error: field_name is required.")


if __name__ == "__main__":
    unittest.main()

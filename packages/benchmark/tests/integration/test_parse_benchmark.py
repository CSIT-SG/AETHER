import pytest
from aether_benchmark.linter import ValidationError, lint_rubric


# --- Valid Case ---
def test_valid_rubric():
    yaml_input = """
name: "Valid Test"
version: "1.0.0"
rubrics:
  - id: "test_1"
    function_address: "0x123"
    weight: 1.0
    criteria:
      - description: "Is valid"
"""
    assert lint_rubric(yaml_input).name == "Valid Test"


# --- Invalid Cases ---
def test_invalid_hex_address():
    yaml_input = """
name: "Bad Hex"
version: "1.0.0"
rubrics:
  - id: "test_2"
    function_address: "invalid_address"
    weight: 1.0
    criteria:
      - description: "Must fail"
"""
    with pytest.raises(ValidationError):
        lint_rubric(yaml_input)


def test_missing_required_field():
    yaml_input = """
name: "Missing Weight"
version: "1.0.0"
rubrics:
  - id: "err"
    function_address: "0x123"
    criteria:
      - description: "Missing weight"
"""
    with pytest.raises(ValidationError):
        lint_rubric(yaml_input)


def test_negative_weight():
    yaml_input = """
name: "Negative Weight"
version: "1.0.0"
rubrics:
  - id: "err"
    function_address: "0x123"
    weight: -1.0
    criteria:
      - description: "Weight must be > 0"
"""
    with pytest.raises(ValidationError):
        lint_rubric(yaml_input)

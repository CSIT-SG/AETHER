from pathlib import Path

import pytest
from aether_benchmark.tasks.parse_benchmark import ParseBenchmarkTask
from aether_benchmark.tasks.parse_benchmark.models import RubricsSchema


@pytest.mark.asyncio
async def test_valid_rubric(tmp_path: Path) -> None:
    rubric_path = tmp_path / "valid_rubric.yaml"
    rubric_path.write_text(
        """
name: "Reference Handler Analysis"
version: "1.0.0"
description: "Evaluates the quality of reverse-engineered packet processing functions."

rubrics:
  - name: "packet_parsing_logic"
    description: "Evaluates packet headers at 0x4010A0 (Main Parser)."
    weight: 2.0
    criteria:
      - "Constants are replaced with named enums or defines"
      - "Struct pointer usage is correctly applied for packet headers"
""".strip(),
        encoding="utf-8",
    )

    parsed = await ParseBenchmarkTask().start(RubricsSchema, rubric_path)

    assert parsed.name == "Reference Handler Analysis"
    assert parsed.rubrics[0].name == "packet_parsing_logic"
    assert parsed.rubrics[0].weight == 2.0
    assert parsed.rubrics[0].criteria[0] == "Constants are replaced with named enums or defines"


@pytest.mark.asyncio
async def test_missing_required_field(tmp_path: Path) -> None:
    rubric_path = tmp_path / "missing_field.yaml"
    rubric_path.write_text(
        """
name: "Broken Rubric"
version: "1.0.0"
rubrics:
  - description: "Missing name field"
    criteria:
      - "This should fail"
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        await ParseBenchmarkTask().start(RubricsSchema, rubric_path)


@pytest.mark.asyncio
async def test_negative_weight(tmp_path: Path) -> None:
    rubric_path = tmp_path / "negative_weight.yaml"
    rubric_path.write_text(
        """
name: "Broken Weight"
version: "1.0.0"
rubrics:
  - name: "bad_weight"
    weight: -1.0
    criteria:
      - "This should fail"
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        await ParseBenchmarkTask().start(RubricsSchema, rubric_path)


@pytest.mark.asyncio
async def test_default_weight_is_used_when_omitted(tmp_path: Path) -> None:
    rubric_path = tmp_path / "default_weight.yaml"
    rubric_path.write_text(
        """
name: "Default Weight"
version: "1.0.0"
rubrics:
  - name: "documentation_standards"
    criteria:
      - "Documentation is present"
""".strip(),
        encoding="utf-8",
    )

    parsed = await ParseBenchmarkTask().start(RubricsSchema, rubric_path)
    assert parsed.rubrics[0].weight == 1.0


@pytest.mark.asyncio
async def test_string_criteria_is_allowed(tmp_path: Path) -> None:
    rubric_path = tmp_path / "string_criteria.yaml"
    rubric_path.write_text(
        """
name: "String Criteria"
version: "1.0.0"
rubrics:
  - name: "checksum_validation"
    weight: 1.5
    criteria:
      - "Checksum values are validated before use"
""".strip(),
        encoding="utf-8",
    )

    parsed = await ParseBenchmarkTask().start(RubricsSchema, rubric_path)
    assert parsed.rubrics[0].criteria[0] == "Checksum values are validated before use"


@pytest.mark.asyncio
async def test_missing_rubrics_key_is_rejected(tmp_path: Path) -> None:
    rubric_path = tmp_path / "missing_rubrics.yaml"
    rubric_path.write_text(
        """
name: "Missing Rubrics"
version: "1.0.0"
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        await ParseBenchmarkTask().start(RubricsSchema, rubric_path)


@pytest.mark.asyncio
async def test_invalid_yaml_is_rejected(tmp_path: Path) -> None:
    rubric_path = tmp_path / "invalid_yaml.yaml"
    rubric_path.write_text(
        """
name: "Bad YAML"
version: "1.0.0"
rubrics:
  - name: "broken"
    criteria: [
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        await ParseBenchmarkTask().start(RubricsSchema, rubric_path)

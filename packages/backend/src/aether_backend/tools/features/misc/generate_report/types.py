from typing import TypedDict


class GeneratedReport(TypedDict):
    report: str
    yara_rules: list[str]

import pytest


@pytest.fixture(autouse=True)
def _pin_package_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the resolved package version so rubric-version tests are independent of the
    real aether_benchmark release version."""
    monkeypatch.setattr(
        "aether_benchmark.tasks.parse_benchmark.models.get_version", lambda: "1.0.0"
    )

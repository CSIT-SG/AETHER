import pytest


def test_runner(get_binary):
    binary = get_binary("test_runner")  # returns absolute Path
    assert binary.exists()

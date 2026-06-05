
from aether_test_fixtures import GetBinary

def test_runner(get_binary: GetBinary) -> None:
    binary = get_binary("basic")  # returns absolute Path
    assert binary.exists()

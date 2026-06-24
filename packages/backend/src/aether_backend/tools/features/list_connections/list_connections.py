from aether_backend.utils.effect import Program, Return


async def list_connections_cb(ids: list[str]) -> Program:
    yield Return(ids)

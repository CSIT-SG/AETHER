from aether_backend.utils.effect import Program, Return


async def list_rpc_connections(ids: list[str]) -> Program:
    yield Return(ids)

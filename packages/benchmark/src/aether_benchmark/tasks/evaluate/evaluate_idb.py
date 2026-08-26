from aether_backend.utils.get_rpc_service import AnyService
from pydantic import BaseModel

from aether_benchmark.cli import BenchmarkArgs, IdbTarget
from aether_benchmark.utils.task import Task


class EvaluateIDBTask[T: BaseModel](Task[[AnyService, BenchmarkArgs, T], T]):
    async def start(self, service: AnyService, args: BenchmarkArgs, schema: T) -> T:
        """Evaluate a rubric against an IDB using the RPC service."""
        if not isinstance(args.target, IdbTarget):
            raise ValueError("EvaluateIDBTask requires an IdbTarget")

        # Here you would implement the logic to evaluate the rubric against the IDB
        # using the provided service. This is a placeholder for demonstration.
        # You might call methods on the service to retrieve evidence and then
        # evaluate it against the rubric defined in schema.

        # For now, we just return the schema as is.
        return schema

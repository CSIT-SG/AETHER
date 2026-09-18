from datetime import datetime

from pydantic import BaseModel


# metadata for date and time of benchmark run, time taken (in seconds), model used(benchmark), and tokens (benchmark) used
class BenchmarkMetadata(BaseModel):
    run_at: datetime
    time_taken_s: float
    model: str
    tokens_used: int | None = None

from pydantic import BaseModel


class Concurrency(BaseModel):
    """Bounds on async parallelism. Tune via CONCURRENCY__<field>=N."""

    # Cap concurrent LLM calls below the deployment's per-minute rate limit.
    file_info_semaphore: int = 500
    re_workers: int = 5
    extractor_workers: int = 5
    llm_eval_parallel: int = 4

from pydantic import BaseModel


class Concurrency(BaseModel):
    """Bounds on async parallelism. Tune via CONCURRENCY__<field>=N."""

    file_info_semaphore: int = 500
    re_workers: int = 12
    extractor_workers: int = 5
    llm_eval_parallel: int = 4
    cve_workers: int = 12
    kb_downloads: int = 6

from pydantic import BaseModel


class Concurrency(BaseModel):
    """Bounds on async parallelism. Tune via CONCURRENCY__<field>=N."""

    # Max concurrent file-description batches in flight (each batch ~15 files).
    # Capped low so the upstream Azure deployment isn't saturated by per-CVE
    # indexing — the previous 500 produced server-side queueing where late
    # requests reported elapsed_s well over 100s on a 95-token prompt.
    file_info_semaphore: int = 10
    re_workers: int = 12
    extractor_workers: int = 5
    llm_eval_parallel: int = 4
    cve_workers: int = 12
    kb_downloads: int = 6

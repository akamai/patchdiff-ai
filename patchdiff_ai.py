import asyncio
import sys

from common import AgentModels, Timer, Threshold, logger, console
from args import get_cve_list
from supervisor.supervisor import Supervisor


# snapshot2 = tracemalloc.take_snapshot()


async def run(cve: str, config: dict = None):
    pd_ai = Supervisor()
    async for step in pd_ai.run(cve=cve, config=config):
        pass

    return True


async def patch_wedensday_assistant(argv: list[str]):
    cve_list = get_cve_list(argv)
    if cve_list is None or len(cve_list) == 0:
        return

    with Timer("Patch Wednesday Assistant"):
        config = {
            "interrupt": False if len(cve_list) > 1 else True,
            "threshold": Threshold(
                candidates=7.5, security_modification=0.25, report=0.1
            ),
            # 'evaluate': True
        }
        console.info(f"[*] Start the system with config: {config}")
        tasks = [await asyncio.to_thread(run, cve=c, config=config) for c in cve_list]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        logger.debug(f"Results: {results}")

    console.info("[+] Done.")


if __name__ == "__main__":
    try:
        asyncio.run(patch_wedensday_assistant(sys.argv[1:]), debug=True)
    except (EOFError, KeyboardInterrupt):
        pass

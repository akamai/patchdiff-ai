import argparse
import asyncio
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from common import logger


@dataclass
class ExecArgs:
    target: Path
    log: str = None
    script: Path = Path("patch_analysis/idapython/analyze.py")
    args: list = None
    ida_path: Path = Path(r"C:\Program Files\IDA Pro 8.0\idat64.exe")


def is_valid_args(args: ExecArgs):
    if not args.ida_path.is_file():
        logger.error(f"ERROR: IDA executable not found at {args.ida_path!r}")
        return False
    if not args.script.is_file():
        logger.error(f"ERROR: IDAPython script not found at {args.script!r}")
        return False
    if not args.target.exists():
        logger.error(f"ERROR: Target file not found at {args.target!r}")
        return False

    return True


def analyze_executable(args: ExecArgs | argparse.Namespace):
    if not is_valid_args(args):
        return -1, None, None

    cmd = [
        f'"{str(args.ida_path)}"',
        f'-L"{args.log}"' if args.log else '',
        "-A",
        f'-S"{args.script}"',
        f'"{str(args.target)}"'
    ]

    try:
        result = subprocess.run(
            " ".join(cmd),
            shell=True,
            check=False,
            universal_newlines=True
        )
    except Exception as e:
        print(f"Failed to launch IDA: {e}", file=sys.stderr)
        return -1

    return result.returncode


async def aanalyze_executable(args: ExecArgs):
    if not is_valid_args(args):
        return -1, None, None

    cmd = f'"{args.ida_path}"'
    if args.log:
        cmd += f' -L"{args.log}"'

    cmd += ' -A'

    script = [args.script]
    if args.args:
        script.extend(args.args)

    esc_script = subprocess.list2cmdline([subprocess.list2cmdline(script)])
    cmd += f" -S{esc_script}"

    cmd += f' "{args.target}"'

    process = await asyncio.create_subprocess_shell(cmd)
    await process.wait()
    return process.returncode


async def batch_analysis(files: list[ExecArgs], condition: Callable[[ExecArgs], bool] = lambda _: True):
    while files:
        current: list[ExecArgs] = []
        remains: list[ExecArgs] = []
        for file in files:
            if not any(x for x in current if x.target == file.target):
                current.append(file)
            else:
                remains.append(file)

        tasks = [aanalyze_executable(file) for file in current if condition(file)]

        await asyncio.gather(*tasks)
        files = remains


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run IDA Pro headless analysis on a target file."
    )
    parser.add_argument(
        "--ida-path",
        type=Path,
        default=Path(r"C:\Program Files\IDA Pro 8.0\idat64.exe"),
        help="Full path to idat64.exe"
    )
    parser.add_argument(
        "--log",
        type=str,
        default="log.txt",
        help="Log file path (relative or absolute)"
    )
    parser.add_argument(
        "--script",
        type=Path,
        default=Path("idapython/main.py"),
        help="Path to your IDAPython script"
    )
    parser.add_argument(
        "target",
        type=Path,
        help="The binary or SYS file to analyze"
    )

    args = parser.parse_args()

    analyze_executable(args)

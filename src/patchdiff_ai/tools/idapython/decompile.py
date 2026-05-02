#!/usr/bin/env python3
"""IDAPython: decompile a list of function EAs to __funcs__/<ea>.c."""

import argparse
from pathlib import Path

import ida_auto
import ida_hexrays
import ida_ida
import ida_idp
import ida_loader
import idaapi
import idc


def parse_args() -> list[int]:
    parser = argparse.ArgumentParser(prog="batch_decompile_funcs.py")
    parser.add_argument(
        "func_list",
        nargs="+",
        type=lambda x: int(x, 16),
        metavar="ea",
        help="Function start address (hex)",
    )
    ns = parser.parse_args(idc.ARGV[1:])
    return ns.func_list


_DECOMPILERS: dict[int, str] = {
    ida_idp.PLFM_386: "hexrays",
    ida_idp.PLFM_ARM: "hexarm",
    ida_idp.PLFM_PPC: "hexppc",
    ida_idp.PLFM_MIPS: "hexmips",
}


def init_hexrays() -> bool:
    cpu = ida_idp.ph.id
    plugin = _DECOMPILERS.get(cpu)
    if plugin is None:
        print(f"[!] Unsupported processor family id={cpu}")
        return False
    if ida_ida.inf_is_64bit():
        plugin = "hexx64" if cpu == ida_idp.PLFM_386 else f"{plugin}64"
    if not ida_loader.load_plugin(plugin):
        print(f"[!] Failed to load decompiler plug-in '{plugin}'")
        return False
    if not ida_hexrays.init_hexrays_plugin():
        print(f"[!] Hex-Rays initialisation failed for '{plugin}'")
        return False
    return True


def decompile_to_file(ea: int, out_dir: Path) -> None:
    file_path = out_dir / f"{ea:X}.c"
    print(f"[*] {ea:x}: decompiling...")
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            raise RuntimeError("Hex-Rays returned None")
        text = str(cfunc) + "\n"
    except Exception as exc:
        print(f"Decompilation failure at {ea:#x}: {exc.__class__.__name__}: {exc}")
        return
    file_path.write_text(text, encoding="utf-8")


def main() -> None:
    e_code = 0
    try:
        ida_auto.auto_wait()
        func_eas = parse_args()
        if not init_hexrays():
            raise RuntimeError("Decompiler initialization failed")
        input_path = Path(idc.get_input_file_path()).resolve()
        out_dir = input_path.parent / "__funcs__"
        out_dir.mkdir(exist_ok=True)
        for ea in func_eas:
            decompile_to_file(ea, out_dir)
        print("[+] All requested functions processed. Output in", out_dir)
    except Exception:
        e_code = 1
        raise
    finally:
        # Explicit save before qexit so a crash during IDA's final cleanup
        # doesn't leave .id0/.id1/.id2/.nam/.til sidecars stranded.
        idc.save_database("", 0)
        idaapi.qexit(e_code)


if __name__ == "__main__":
    main()

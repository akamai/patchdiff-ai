#!/usr/bin/env python3
"""IDAPython: auto-analyze and export a BinExport file."""

import idaapi
import ida_auto
import ida_pro
import idc
from pathlib import Path


def main() -> None:
    ida_auto.auto_wait()
    idaapi.flush_buffers()

    idb_path = Path(idc.get_input_file_path())
    output_file = str(idb_path.resolve())
    export_path = (output_file + ".BinExport").replace("\\", "/")
    idaapi.ida_expr.eval_idc_expr(
        None, idaapi.BADADDR, f'BinExportBinary("{export_path}");'
    )
    # Explicit save before qexit: IDA sometimes crashes during final cleanup
    # (BinExport teardown has triggered 0xC0000374 heap corruption on shell32),
    # which would otherwise leave the database unmerged and the .id0/.id1/.id2
    # /.nam/.til sidecars stranded on disk.
    idc.save_database("", 0)
    ida_pro.qexit(0)


if __name__ == "__main__":
    main()

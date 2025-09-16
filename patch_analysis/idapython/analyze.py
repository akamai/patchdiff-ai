#!/usr/bin/env python3
import idaapi
import ida_auto
import ida_pro
import idc
from pathlib import Path


def main():
    # ida_auto.auto_mark_range(0, idaapi.BADADDR, ida_auto.AU_FINAL)
    ida_auto.auto_wait()

    idaapi.flush_buffers()

    idb_path = Path(idc.get_input_file_path())
    output_file = str(idb_path.resolve())

    # idc.gen_file(idc.OFILE_ASM, output_file + ".asm", 0, idaapi.BADADDR, 0)
    # idc.gen_file(idc.OFILE_MAP, output_file + ".map", 0, idaapi.BADADDR, 0)
    # idc.gen_file(idc.OFILE_LST, output_file + ".lst", 0, idaapi.BADADDR, 0)
    # idc.gen_file(idc.OFILE_IDC, output_file + ".idc", 0, idaapi.BADADDR, idc.GENFLG_MAPDMNG)
    #
    export_path = (output_file + ".BinExport").replace('\\', '/')
    # print(export_path)
    idaapi.ida_expr.eval_idc_expr(None, idaapi.BADADDR, 'BinExportBinary("' + export_path + '");')

    ida_pro.qexit(0)


if __name__ == "__main__":
    main()

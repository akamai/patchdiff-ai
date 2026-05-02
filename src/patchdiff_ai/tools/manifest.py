"""WCP manifest decompressor (mostly verbatim port; safer string_at handling)."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)


class _BlobData(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("length", ctypes.c_size_t),
        ("fill", ctypes.c_size_t),
        ("pData", ctypes.c_void_p),
    ]


class WcpManifestExtractor:
    """Wraps wcp.dll APIs to inflate Microsoft compressed manifests."""

    def __init__(self, dll_path: Path) -> None:
        try:
            self.wcp = ctypes.WinDLL(str(dll_path))
        except OSError as exc:
            raise RuntimeError(f"Failed to load wcp.dll at {dll_path}: {exc}") from exc
        self._setup()

    def _setup(self) -> None:
        self.GetCompressedFileType = self.wcp[
            "?GetCompressedFileType@Rtl@WCP@Windows@@YAKPEBU_LBLOB@@@Z"
        ]
        self.GetCompressedFileType.restype = ctypes.c_ulong
        self.GetCompressedFileType.argtypes = [ctypes.POINTER(_BlobData)]

        self.InitializeDeltaCompressor = self.wcp[
            "?InitializeDeltaCompressor@Rtl@Windows@@YAJPEAX@Z"
        ]
        self.InitializeDeltaCompressor.restype = ctypes.c_long
        self.InitializeDeltaCompressor.argtypes = [ctypes.c_void_p]

        self.DeltaDecompressBuffer = self.wcp[
            "?DeltaDecompressBuffer@Rtl@Windows@@YAJKPEAU_LBLOB@@_K0PEAVAutoDeltaBlob@12@@Z"
        ]
        self.DeltaDecompressBuffer.restype = ctypes.c_long
        self.DeltaDecompressBuffer.argtypes = [
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(_BlobData),
            ctypes.POINTER(_BlobData),
        ]

        self.LoadFirstResourceLanguageAgnostic = self.wcp[
            "?LoadFirstResourceLanguageAgnostic@Rtl@Windows@@YAJKPEAUHINSTANCE__@@PEBG1PEAU_LBLOB@@@Z"
        ]
        self.LoadFirstResourceLanguageAgnostic.restype = ctypes.c_long
        self.LoadFirstResourceLanguageAgnostic.argtypes = [
            ctypes.c_ulong,
            wintypes.HINSTANCE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]

    def extract(self, input_path: Path, output_path: Path | None = None) -> bytes:
        output_path = output_path or input_path

        try:
            data = Path(input_path).read_bytes()
        except OSError as exc:
            raise IOError(f"Failed to read input: {exc}") from exc

        size = len(data)
        buf = ctypes.create_string_buffer(data, size)

        in_blob = _BlobData()
        in_blob.length = size
        in_blob.fill = size
        in_blob.pData = ctypes.cast(buf, ctypes.c_void_p)

        self.GetCompressedFileType(ctypes.byref(in_blob))

        if self.InitializeDeltaCompressor(None) < 0:
            raise RuntimeError("Failed to initialize delta compressor")

        dict_data = (ctypes.c_uint64 * 3)()
        if (
            self.LoadFirstResourceLanguageAgnostic(
                0,
                self.wcp._handle,
                ctypes.c_void_p(0x266),
                ctypes.c_void_p(1),
                ctypes.byref(dict_data),
            )
            < 0
        ):
            raise RuntimeError("Failed to load resource dictionary")

        out_blob = _BlobData()
        if (
            self.DeltaDecompressBuffer(
                2,
                ctypes.byref(dict_data),
                4,
                ctypes.byref(in_blob),
                ctypes.byref(out_blob),
            )
            < 0
        ):
            raise RuntimeError("Failed to decompress data")

        if not out_blob.pData or out_blob.length == 0:
            raise RuntimeError("Delta decompressor returned an empty blob")

        result = ctypes.string_at(out_blob.pData, out_blob.length)

        try:
            Path(output_path).write_bytes(result)
        except OSError as exc:
            raise IOError(f"Failed to write output: {exc}") from exc
        return result

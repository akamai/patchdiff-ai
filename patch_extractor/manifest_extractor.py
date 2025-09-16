import ctypes
from ctypes import wintypes
from pathlib import Path

from common import logger


class ManifestExtractor:
    class BlobData(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("length", ctypes.c_size_t),
            ("fill", ctypes.c_size_t),
            ("pData", ctypes.c_void_p)
        ]

    def __init__(self, dll_path=Path("wcp.dll"), verbose=False):

        # Load wcp.dll
        try:
            self.wcp = ctypes.WinDLL(str(dll_path))
            logger.debug(f"Successfully loaded {dll_path}")
            self._setup_functions()
        except Exception as e:
            raise RuntimeError(f"Failed to load WCP DLL: {e}")

    def _setup_functions(self):
        # GetCompressedFileType
        self.GetCompressedFileType = self.wcp["?GetCompressedFileType@Rtl@WCP@Windows@@YAKPEBU_LBLOB@@@Z"]
        self.GetCompressedFileType.restype = ctypes.c_ulong
        self.GetCompressedFileType.argtypes = [ctypes.POINTER(self.BlobData)]

        # InitializeDeltaCompressor
        self.InitializeDeltaCompressor = self.wcp["?InitializeDeltaCompressor@Rtl@Windows@@YAJPEAX@Z"]
        self.InitializeDeltaCompressor.restype = ctypes.c_long
        self.InitializeDeltaCompressor.argtypes = [ctypes.c_void_p]

        # DeltaDecompressBuffer
        self.DeltaDecompressBuffer = self.wcp[
            "?DeltaDecompressBuffer@Rtl@Windows@@YAJKPEAU_LBLOB@@_K0PEAVAutoDeltaBlob@12@@Z"]
        self.DeltaDecompressBuffer.restype = ctypes.c_long
        self.DeltaDecompressBuffer.argtypes = [
            ctypes.c_ulong,  # DeltaFlagType
            ctypes.c_void_p,  # pDictionary
            ctypes.c_ulong,  # headerSize
            ctypes.POINTER(self.BlobData),  # inData
            ctypes.POINTER(self.BlobData)  # outData
        ]

        # LoadFirstResourceLanguageAgnostic
        self.LoadFirstResourceLanguageAgnostic = self.wcp[
            "?LoadFirstResourceLanguageAgnostic@Rtl@Windows@@YAJKPEAUHINSTANCE__@@PEBG1PEAU_LBLOB@@@Z"]
        self.LoadFirstResourceLanguageAgnostic.restype = ctypes.c_long
        self.LoadFirstResourceLanguageAgnostic.argtypes = [
            ctypes.c_ulong,  # unused
            wintypes.HINSTANCE,  # hModule
            ctypes.c_void_p,  # lpType (special value)
            ctypes.c_void_p,  # lpName (special value)
            ctypes.c_void_p  # pOutDict
        ]

    def extract(self, input_path, output_path=None):
        if output_path is None:
            output_path = input_path

        try:
            with open(input_path, "rb") as f:
                manifest_data = f.read()
        except Exception as e:
            raise IOError(f"Failed to read input file: {e}")

        data_size = len(manifest_data)
        logger.debug(f"Input file size: {data_size} bytes")

        manifest_buffer = ctypes.create_string_buffer(manifest_data, data_size)

        in_data = self.BlobData()
        in_data.length = data_size
        in_data.fill = data_size
        in_data.pData = ctypes.cast(manifest_buffer, ctypes.c_void_p)

        file_type = self.GetCompressedFileType(ctypes.byref(in_data))
        logger.debug(f"Compression type: {file_type}")

        result = self.InitializeDeltaCompressor(None)
        if result < 0:
            raise RuntimeError("Failed to initialize delta compressor")

        dict_data = (ctypes.c_uint64 * 3)()

        result = self.LoadFirstResourceLanguageAgnostic(
            0,  # unused
            self.wcp._handle,  # HMODULE
            ctypes.c_void_p(0x266),  # lpType (special value)
            ctypes.c_void_p(1),  # lpName (special value)
            ctypes.byref(dict_data)
        )

        if result < 0:
            raise RuntimeError("Failed to load resource dictionary")

        out_data = self.BlobData()

        result = self.DeltaDecompressBuffer(
            2,  # type (2 from original code)
            ctypes.byref(dict_data),  # dictionary
            4,  # headerSize (4 from original code)
            ctypes.byref(in_data),  # input data
            ctypes.byref(out_data)  # output data
        )

        if result < 0:
            raise RuntimeError("Failed to decompress data")

        outbuffer = ctypes.string_at(out_data.pData, out_data.length)
        logger.debug(f"Decompressed size: {out_data.length} bytes")

        try:
            with open(output_path, "wb") as outfile:
                outfile.write(outbuffer)
                logger.debug(f"Decompressed data written to {output_path}")
        except Exception as e:
            raise IOError(f"Failed to write output file: {e}")

        return outbuffer

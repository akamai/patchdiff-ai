import ctypes
import mmap
import os
import sys
import zlib
from ctypes import (CDLL, FormatError, POINTER, LittleEndianStructure, Union, byref,
                    c_size_t, c_ubyte, c_uint64, cast, windll, wintypes)
from pathlib import Path
import glob
import xml.etree.ElementTree as ET

from common import get_winsxs, logger


class DeltaInput(LittleEndianStructure):
    class StartUnion(Union):
        _fields_ = [('lpcStart', wintypes.LPVOID),
                    ('lpStart', wintypes.LPVOID)]

    _anonymous_ = ('start_union',)
    _fields_ = [('start_union', StartUnion),
                ('uSize', c_size_t),
                ('Editable', wintypes.BOOL)]


class DeltaOutput(LittleEndianStructure):
    _fields_ = [('lpStart', wintypes.LPVOID),
                ('uSize', c_size_t)]


def cast_void_p(buffer: memoryview):
    if isinstance(buffer.obj, mmap.mmap):
        addr = ctypes.addressof(ctypes.c_byte.from_buffer(buffer.obj))
        return ctypes.wintypes.LPVOID(addr)
    if isinstance(buffer.obj, bytes):
        return ctypes.cast(buffer.obj, ctypes.wintypes.LPVOID)

    raise RuntimeError(f"Underline object is neither bytes or mmap")


class PatchTools:
    delta_modules: list[ctypes.WinDLL] = []

    @staticmethod
    def load_delta_modules(modules: list[str]):
        for dll in modules:
            if any(m for m in PatchTools.delta_modules if m._name == dll):
                continue
            try:
                PatchTools.delta_modules.append(windll.__getattr__(dll))
            except OSError:
                logger.debug(f'Failed to load patch tools module {dll}')

    def __init__(self, module: Path | None = None):
        if not PatchTools.delta_modules:
            default_dlls = [str(Path(__file__).resolve().parent / "UpdateCompression.dll"), 'UpdateCompression', 'msdelta']
            PatchTools.load_delta_modules(default_dlls)

            if not PatchTools.delta_modules:
                raise RuntimeError(
                    "Failed to load required DLL. Please ensure UpdateCompression.dll or "
                    "msdelta.dll is available.")

        if module:
            PatchTools.load_delta_modules([str(module.resolve())])

        self.apply_delta, self.free_delta = self._load_api(PatchTools.delta_modules[0])
        self.winsxs = get_winsxs()

    @staticmethod
    def _load_api(module):
        apply_delta = module.ApplyDeltaB
        apply_delta.argtypes = [c_uint64, DeltaInput, DeltaInput, POINTER(DeltaOutput)]
        apply_delta.restype = wintypes.BOOL

        free_delta = module.DeltaFree
        free_delta.argtypes = [wintypes.LPVOID]
        free_delta.restype = wintypes.BOOL

        return apply_delta, free_delta

    @staticmethod
    def is_patch(patch: memoryview | bytes):
        try:
            PatchTools.validate_patch(memoryview(patch))
        except (ValueError, TypeError):
            return False

        return True

    @staticmethod
    def validate_patch(patch: memoryview):
        if len(patch) < 8:
            raise ValueError('Patch size is too small')

        sig = patch[:6].tobytes()

        if not sig.startswith(b"PA") or sig.endswith(b'PA'):
            expected_crc = int.from_bytes(patch[:4].tobytes(), 'little')
            patch_data: memoryview = memoryview(patch.obj[4:])
            if zlib.crc32(patch_data) != expected_crc:
                raise ValueError("CRC32 check failed. Patch corrupted or invalid")
        elif sig.startswith(b"PA"):
            patch_data: memoryview = patch
        else:
            raise ValueError(f"Invalid patch format in {sig}")

        return patch_data

    @staticmethod
    def map_file(path, offset=0, length=0, access=mmap.ACCESS_COPY):
        with open(path, 'r+b') as f:
            return mmap.mmap(f.fileno(), length, offset=offset, access=access)

    def _apply(self, buffer: memoryview | None, patch: memoryview):
        patch_input = DeltaInput()

        patch_data = self.validate_patch(patch)
        patch_input.lpStart, patch_input.uSize = cast_void_p(patch_data), patch_data.nbytes
        patch_input.Editable = False

        source = DeltaInput()
        if buffer is not None:
            source.lpStart = cast_void_p(buffer)
            source.uSize = buffer.nbytes
            source.Editable = False
        else:
            source.lpStart = None
            source.uSize = 0
            source.Editable = False

        output = DeltaOutput()

        flags = 0  # DELTA_APPLY_FLAG_ALLOW_PA19 = 1
        success = self.apply_delta(flags, source, patch_input, byref(output))

        if not success:
            error_code = ctypes.windll.kernel32.GetLastError()
            raise RuntimeError(f"Failed to apply patch: 0x{error_code:X}")

        # Extract the result
        result_size = output.uSize
        result_ptr = output.lpStart

        # Copy the result to a Python bytes object
        result_array = (c_ubyte * result_size).from_address(result_ptr)
        result = bytes(result_array)

        # Free the memory allocated by ApplyDeltaB
        self.free_delta(result_ptr)

        return result

    def apply(self, buffer: memoryview | None, patch: memoryview) -> bytes | None:
        gen = (x for x in PatchTools.delta_modules)
        try:
            result = self._apply(buffer, patch)
            if result:
                return result
        except ValueError as e:
            logger.error(e)
            raise RuntimeError('This is not a valid patch')
        except RuntimeError as e:
            try:
                m = next(gen)
                self.apply_delta, self.free_delta = self._load_api(m)
            except StopIteration:
                logger.error(e)
                raise e

    def find_base_and_load(self, name):
        if not self.winsxs:
            raise RuntimeError("WinSxS directory not found")

        # Find matching directories sorted by newest first
        matching_dirs = sorted(self.winsxs.glob(f"*_{name}_*"),
                               key=lambda p: p.stat().st_ctime, reverse=True)

        if not matching_dirs:
            raise FileNotFoundError(f"No matching directory found for {name}")

        for dir_path in matching_dirs:
            # Direct DLL check
            dll_path = dir_path / name
            if dll_path.exists():
                return dll_path.read_bytes()

            r_dir, f_dir = dir_path / "r", dir_path / "f"
            reverse_patches = sorted(r_dir.glob("*.pa_")) if r_dir.exists() and r_dir.is_dir() else []

            if not reverse_patches:
                continue

            # Find base version to patch
            try:
                current = None
                if f_dir.exists() and f_dir.is_dir():
                    forward_dlls = list(f_dir.glob(f"{name}"))
                    current = forward_dlls[0].read_bytes() if forward_dlls else None

                if not current:
                    system32_path = Path(os.environ["SystemRoot"]) / "System32" / name
                    current = system32_path.read_bytes() if system32_path.exists() else None

                if not current:
                    continue

                # Apply reverse patches
                for patch_path in reverse_patches:
                    try:
                        current = self.apply(current, patch_path.read_bytes())
                    except RuntimeError as e:
                        print(f"Warning: Failed to apply patch {patch_path}: {e}")

                return current

            except (FileNotFoundError, IOError):
                continue

        raise FileNotFoundError(f"Could not find or reconstruct base for {name}")

    def get_manifest(self, name):
        if not self.winsxs:
            raise RuntimeError("WinSxS directory not found")

        manifests_dir = self.winsxs / "Manifests"
        if not manifests_dir.exists():
            raise FileNotFoundError("Manifests directory not found")

        # Find matching manifests
        pattern = f"*_{name}_*.manifest"
        matching_manifests = list(manifests_dir.glob(pattern))

        if not matching_manifests:
            raise FileNotFoundError(f"No manifest found for {name}")

        # Sort by creation time (newest first)
        matching_manifests.sort(key=lambda p: p.stat().st_ctime, reverse=True)

        # Return the content of the most recent manifest
        with open(matching_manifests[0], "rb") as f:
            return f.read()

    def parse_manifest(self, manifest_data):
        try:
            root = ET.fromstring(manifest_data.decode('utf-8'))

            # Define XML namespaces
            namespaces = {
                'asm': 'urn:schemas-microsoft-com:asm.v1',
                'win': 'urn:schemas-microsoft-com:asm.v3'
            }

            # Extract basic info
            identity = root.find('.//asm:identity', namespaces)
            if identity is not None:
                name = identity.get('name')
                version = identity.get('version')
                architecture = identity.get('processorArchitecture')
                public_key_token = identity.get('publicKeyToken')
            else:
                name = version = architecture = public_key_token = None

            # Extract file info
            files = []
            for file_elem in root.findall('.//win:file', namespaces):
                files.append({
                    'name': file_elem.get('name'),
                    'hash': file_elem.get('hash'),
                    'hashalg': file_elem.get('hashalg')
                })

            return {
                'name': name,
                'version': version,
                'architecture': architecture,
                'public_key_token': public_key_token,
                'files': files
            }
        except Exception as e:
            print(f"Error parsing manifest: {e}")
            return None

# p = PatchTools()
# mm = PatchTools.map_file(
#     r'..\test\extracted_old_windows11.0-kb5051987-x64_199ed7806a74fe78e3b0ef4f2073760000f71972.msu\archives\Windows11.0-KB5051987-x64-3.psf')
# p.apply(None, mm)

"""Windows MSDelta API wrapper. Instance-scoped.

Replaces the static `PatchTools.delta_modules` list and module-level `pt`
in legacy code. DLLs are only unmapped at process exit (see `close()`
for why we don't `FreeLibrary` ourselves).
"""

from __future__ import annotations

import ctypes
import mmap
import zlib
from contextlib import contextmanager
from ctypes import (
    POINTER,
    LittleEndianStructure,
    Union,
    byref,
    c_size_t,
    c_ubyte,
    c_uint64,
    cast,
    windll,
    wintypes,
)
from pathlib import Path
from typing import Iterable

import structlog

log = structlog.get_logger(__name__)


class _DeltaInput(LittleEndianStructure):
    class _StartU(Union):
        _fields_ = [("lpcStart", wintypes.LPVOID), ("lpStart", wintypes.LPVOID)]

    _anonymous_ = ("u",)
    _fields_ = [("u", _StartU), ("uSize", c_size_t), ("Editable", wintypes.BOOL)]


class _DeltaOutput(LittleEndianStructure):
    _fields_ = [("lpStart", wintypes.LPVOID), ("uSize", c_size_t)]


def _cast_void_p(buf: memoryview):
    if isinstance(buf.obj, mmap.mmap):
        addr = ctypes.addressof(ctypes.c_byte.from_buffer(buf.obj))
        return wintypes.LPVOID(addr)
    if isinstance(buf.obj, (bytes, bytearray)):
        return cast(buf.obj, wintypes.LPVOID)
    raise RuntimeError("Underlying object is neither bytes nor mmap")


class DeltaApi:
    """Wraps msdelta / UpdateCompression `ApplyDeltaB` + `DeltaFree`.

    Use one instance per CVE run. `close()` only drops Python-side
    references; the DLLs themselves stay mapped until process exit
    (calling `FreeLibrary` while ctypes still has live `_FuncPtr`
    objects pointing into them crashes `Py_Finalize`).
    """

    def __init__(self, modules: Iterable[Path | str] | None = None) -> None:
        self._modules: list[ctypes.WinDLL] = []
        self.apply_delta = None
        self.free_delta = None

        for mod in modules or []:
            self.load_module(mod)

    @contextmanager
    def lifetime(self):
        try:
            yield self
        finally:
            self.close()

    def load_module(self, mod: Path | str) -> bool:
        """Load a delta-compression DLL. Returns True on success.

        Rebinds `apply_delta` / `free_delta` to the just-loaded DLL each
        time so the **latest** loaded module wins. The pipeline loads the
        bundled `UpdateCompression.dll` first (in `AppContext.__init__`)
        and then each downloaded KB's own `DesktopDeployment.cab/
        UpdateCompression.dll` after extraction (`extractor.load_delta_dlls`).
        Newer KBs ship newer delta formats — only the KB's own DLL knows
        how to apply them. Without rebinding, the older bundled DLL's
        `ApplyDeltaB` rejects the newer patch with a generic Win32 error
        and `recursive_apply` falls back to (`source=None`) which fails
        for forward deltas that genuinely need the source bytes.
        """
        try:
            handle = windll.LoadLibrary(str(mod))
        except OSError as exc:
            log.debug("delta_load_failed", module=str(mod), error=str(exc))
            return False
        if any(getattr(m, "_name", None) == handle._name for m in self._modules):
            return True
        self._modules.append(handle)
        self._bind_api(handle)
        return True

    def _bind_api(self, module: ctypes.WinDLL) -> None:
        apply_delta = module.ApplyDeltaB
        apply_delta.argtypes = [c_uint64, _DeltaInput, _DeltaInput, POINTER(_DeltaOutput)]
        apply_delta.restype = wintypes.BOOL

        free_delta = module.DeltaFree
        free_delta.argtypes = [wintypes.LPVOID]
        free_delta.restype = wintypes.BOOL

        self.apply_delta = apply_delta
        self.free_delta = free_delta

    def has_modules(self) -> bool:
        return bool(self._modules)

    @staticmethod
    def is_patch(patch: bytes | memoryview) -> bool:
        try:
            DeltaApi.validate_patch(memoryview(patch))
        except (ValueError, TypeError):
            return False
        return True

    @staticmethod
    def validate_patch(patch: memoryview) -> memoryview:
        if len(patch) < 8:
            raise ValueError("Patch size is too small")
        sig = patch[:6].tobytes()
        if not sig.startswith(b"PA") or sig.endswith(b"PA"):
            expected_crc = int.from_bytes(patch[:4].tobytes(), "little")
            patch_data = memoryview(patch.obj[4:])
            if zlib.crc32(patch_data) != expected_crc:
                raise ValueError("CRC32 check failed; patch corrupted")
            return patch_data
        if sig.startswith(b"PA"):
            return patch
        raise ValueError(f"Invalid patch format: {sig!r}")

    @staticmethod
    def map_file(path: Path | str, *, access: int = mmap.ACCESS_COPY) -> mmap.mmap:
        # Caller is responsible for closing — used by PsfArchive context manager.
        f = open(path, "r+b")
        return mmap.mmap(f.fileno(), 0, access=access)

    def apply(self, source: memoryview | None, patch: memoryview) -> bytes:
        if self.apply_delta is None:
            raise RuntimeError("DeltaApi has no module loaded")

        patch_data = self.validate_patch(patch)
        patch_in = _DeltaInput()
        patch_in.lpStart = _cast_void_p(patch_data)
        patch_in.uSize = patch_data.nbytes
        patch_in.Editable = False

        src_in = _DeltaInput()
        if source is not None:
            src_in.lpStart = _cast_void_p(source)
            src_in.uSize = source.nbytes
            src_in.Editable = False
        else:
            src_in.lpStart = None
            src_in.uSize = 0
            src_in.Editable = False

        out = _DeltaOutput()
        if not self.apply_delta(0, src_in, patch_in, byref(out)):
            err = ctypes.windll.kernel32.GetLastError()
            raise RuntimeError(f"ApplyDeltaB failed: 0x{err:X}")

        try:
            arr = (c_ubyte * out.uSize).from_address(out.lpStart)
            return bytes(arr)
        finally:
            self.free_delta(out.lpStart)

    def recursive_apply(self, base: bytes | None, patch: bytes | memoryview) -> bytes | None:
        """Iteratively unpack chained patches until a non-patch result is produced."""
        cur = patch
        try:
            while self.is_patch(cur):
                try:
                    nxt = self.apply(memoryview(base) if base is not None else None, memoryview(cur))
                except RuntimeError:
                    nxt = self.apply(None, memoryview(cur))
                cur = nxt
                if not cur:
                    return None
        except RuntimeError:
            return None
        return cur

    def close(self) -> None:
        """Drop Python-side references; let the OS reclaim DLL handles.

        Don't call `FreeLibrary` here: ctypes' `WinDLL` wrappers and live
        `_FuncPtr` objects (`apply_delta`, `free_delta`) still reference
        the DLL's address space. Unmapping those pages mid-shutdown
        produces an access violation in `python311.dll` when the GC
        traverses them during `Py_Finalize`. Process-exit unloads the
        DLLs anyway.
        """
        self._modules.clear()
        self.apply_delta = None
        self.free_delta = None

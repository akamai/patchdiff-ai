"""Local Windows version detection. No `input()`. Returns CVRF (name, id)."""

from __future__ import annotations

import ctypes
import sys
from datetime import datetime
from typing import Mapping

import requests
import structlog

log = structlog.get_logger(__name__)


class _SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", ctypes.c_uint16),
        ("wReserved", ctypes.c_uint16),
        ("dwPageSize", ctypes.c_uint32),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", ctypes.c_void_p),
        ("dwNumberOfProcessors", ctypes.c_uint32),
        ("dwProcessorType", ctypes.c_uint32),
        ("dwAllocationGranularity", ctypes.c_uint32),
        ("wProcessorLevel", ctypes.c_uint16),
        ("wProcessorRevision", ctypes.c_uint16),
    ]


def _reg_value(field: str) -> str | None:
    if sys.platform != "win32":
        return None
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        ) as k:
            return winreg.QueryValueEx(k, field)[0]
    except FileNotFoundError:
        return None


def processor_arch_tokens(arch_map: Mapping[int, tuple[str, ...]]) -> tuple[str, ...]:
    if sys.platform != "win32":
        return ("unknown",)
    si = _SYSTEM_INFO()
    ctypes.windll.kernel32.GetNativeSystemInfo(ctypes.byref(si))
    return arch_map.get(si.wProcessorArchitecture, ("unknown",))


def windows_version_tokens() -> set[str]:
    tokens: set[str] = set()
    if sys.platform != "win32":
        return tokens

    info = sys.getwindowsversion()
    disp = _reg_value("DisplayVersion")
    if disp:
        tokens.add(disp)
    tokens.update(
        processor_arch_tokens(
            {
                0: ("x86", "32-bit"),
                5: ("arm",),
                9: ("x64", "64-bit", "amd64", "x64-based"),
                12: ("arm64", "ARM64-based"),
            }
        )
    )
    if info.service_pack_major:
        tokens.update(f"service pack {info.service_pack_major}".split())

    if info.product_type > 1:
        tokens.add("server")
        product_name = _reg_value("ProductName")
        if isinstance(product_name, str):
            tokens.update(product_name.lower().split())
    else:
        if (info.major, info.minor) == (10, 0):
            name = "windows 11" if info.build >= 22000 else "windows 10"
        elif (info.major, info.minor) == (6, 3):
            name = "windows 8.1"
        elif (info.major, info.minor) == (6, 2):
            name = "windows 8"
        elif (info.major, info.minor) == (6, 1):
            name = "windows 7"
        else:
            name = f"windows {info.major}.{info.minor}"
        tokens.update(name.split())
    return tokens


def is_int(value: str | int) -> bool:
    if isinstance(value, int):
        return True
    if isinstance(value, str):
        try:
            int(value)
            return True
        except ValueError:
            return False
    return False


def get_cvrf_data(cvrf_id: str | None = None) -> dict:
    if cvrf_id is None:
        cvrf_id = datetime.now().strftime("%Y-%b").upper()
    url = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{cvrf_id}"
    return requests.get(url, headers={"Accept": "application/json"}, timeout=30).json()


def load_product_tree(data: dict) -> dict[int, str]:
    return {
        int(p["ProductID"]): p["Value"]
        for p in data["ProductTree"]["FullProductName"]
        if is_int(p["ProductID"])
    }


def get_cvrf_product_name_and_id(machine_tokens: set[str] | None = None) -> tuple[str, int]:
    machine_tokens = machine_tokens or windows_version_tokens()
    log.info("os_tokens", tokens=sorted(machine_tokens))

    data = get_cvrf_data()
    p_tree = load_product_tree(data)
    rank = 0
    name = ""
    pid = 0
    for k, v in p_tree.items():
        n = v.replace("(", "").replace(")", "")
        r = len(machine_tokens & set(n.split()))
        if r > rank:
            rank, name, pid = r, v, k
    return name, pid

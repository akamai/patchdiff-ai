import ctypes
import winreg
from ctypes.wintypes import DWORD, WORD, BYTE, WCHAR
import sys
from common import logger, console
import requests

from patch_downloader.filter_by_platform import pick_ids


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", ctypes.c_void_p),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]


RtlGetVersion = ctypes.windll.ntdll.RtlGetVersion  # always returns real version
GetProductInfo = ctypes.windll.kernel32.GetProductInfo
GetNativeSystemInfo = ctypes.windll.kernel32.GetNativeSystemInfo


# --- Registry helper -------------------------------------------------------
def get_reg_version(field) -> str | None:
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            return winreg.QueryValueEx(k, field)[0]
    except FileNotFoundError:
        return None


def processor_arch_tokens(arch_map: dict[int, tuple[str]]):
    si = SYSTEM_INFO()
    GetNativeSystemInfo(ctypes.byref(si))
    return arch_map.get(si.wProcessorArchitecture, ("unknown",))


# --- Main OS-identification routine ---------------------------------------
def get_windows_version_tokens():
    version_tokens = set()
    info = sys.getwindowsversion()

    version_tokens.update([get_reg_version("DisplayVersion")])
    version_tokens.update(processor_arch_tokens(
        {
            0: ("x86", "32-bit"),
            5: ("arm",),
            9: ("x64", "64-bit", "amd64", "x64-based"),
            12: ("arm64", "ARM64-based"),
        }
    ))
    version_tokens.update(f"service pack {info.service_pack_major}".split() if info.service_pack_major else ())

    if info.product_type > 1:
        version_tokens.update('server')
        product_name = get_reg_version('ProductName')
        version_tokens.update(product_name.lower().split() if isinstance(product_name, str) else ())
    else:
        match (info.major, info.minor):
            case (10, 0):
                name = "windows 11" if info.build >= 22000 else "windows 10"
            case (6, 3):
                name = "windows 8.1"
            case (6, 3):
                name = "windows 8.1"
            case (6, 2):
                name = "windows 8"
            case (6, 1):
                name = "windows 7"
            case _:
                name = f"windows {info.major}.{info.minor}"

        version_tokens.update(name.split())

    #  TODO: add core server https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh846315(v=vs.85)

    return version_tokens


def is_int(value: str | int):
    if isinstance(value, int):
        return True
    elif isinstance(value, str):
        try:
            v = int(value)
            return True
        except ValueError:
            pass

    return False


def get_cvrf_data(cvrf_id="2025-Apr"):
    url = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{cvrf_id}"
    headers = {"Accept": "application/json"}
    data = requests.get(url, headers=headers, timeout=30).json()
    return data

def load_product_tree(data) -> dict[int, str]:
    # Build name → ID map
    return {
        int(p["ProductID"]): p["Value"]
        for p in data["ProductTree"]["FullProductName"]
        if is_int(p["ProductID"])
    }


def get_cvrf_product_name_and_id(machine_id_t: set | None = None):
    if machine_id_t is None:
        machine_id_t = get_windows_version_tokens()

    console.info(f'Windows version tokens: {machine_id_t}')
    data = get_cvrf_data()
    if input("Choose from a list? [y/N] ").lower().startswith("y"):
        res = pick_ids(cvrf=data, query=input('Product name: '), ids=set())
        if res[0]:
            name = res[1][0]
            id = [i for i in res[0]][0]
        logger.info(
            f'CVRF product name is {res}'
        )
    else:
        p_tree = load_product_tree(data)
        rank = 0
        name = ''
        id = 0
        for k, v in p_tree.items():
            n = v.replace('(', '').replace(')', '')
            r = len(machine_id_t & set(n.split()))
            if r > rank:
                rank = r
                name = v
                id = k

    return name, id


if __name__ == "__main__":
    name, id = get_cvrf_product_name_and_id({'server', '2025'})

    print(f'CVRF product name is {name} with id {id}')

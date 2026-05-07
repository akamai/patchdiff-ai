# Prerequisites

Manual downloads required before running PatchDiff-AI. After installing these,
run `patchdiff-ai install` to bootstrap the remaining components (idalib + IDA
9.3 BinDiff/BinExport plugins).

## Manual downloads

| Component | Download |
|-----------|----------|
| Python 3.11 (x64) | https://www.python.org/downloads/release/python-3119/ |
| 7-Zip 22+ | https://www.7-zip.org/download.html |
| Windows Server 2025 (evaluation ISO) | https://software-static.download.prss.microsoft.com/pr/download/17763.737.190906-2324.rs5_release_svc_refresh_SERVERHYPERCORE_OEM_x64FRE_en-us_1.iso |
| Windows 11 (ISO) | https://www.microsoft.com/en-gb/software-download/windows11 |

Checkout the https://uupdump.net/ for older versions

The Windows ISOs are used to build a local WinSxS index via
`patchdiff-ai windows index <winsxs-dir> --product-name "..." --slug ...` — they
are not bundled because of size.

IDA Pro 8.x or 9.x and BinDiff 8.0 + BinExport 12+ are also required at
runtime; install IDA from your licensed source. The bundled BinDiff/BinExport
DLLs under [bindiff_ida_9.3/](bindiff_ida_9.3/) are pinned to IDA 9.3's SDK
ABI — install IDA 9.3 if you want `patchdiff-ai install` to wire them up
automatically.

## Automated install

After the manual downloads above, bootstrap the per-user config and then
run the installer:

```powershell
patchdiff-ai init           # writes %APPDATA%\patchdiff-ai\config.json
patchdiff-ai install        # idalib + IDA 9.3 BinDiff/BinExport plugins
```

`patchdiff-ai init` writes a starter `config.json` you can edit to point
at credentials and tool paths. (If you skip it, the first command that
needs settings auto-creates the same template.) `patchdiff-ai install`
iterates every registered platform provider and installs its
prerequisites. On Windows that means:

1. `idalib` — pip-installs the `idapro-*-py3-none-any.whl` shipped under
   `<IDA root>/idalib/python/` and runs `py-activate-idalib.py` against the
   newest IDA 9.0+ install.
2. **IDA 9.3 plugins** — copies `bindiff8_ida64.dll` and
   `binexport12_ida64.dll` from [bindiff_ida_9.3/](bindiff_ida_9.3/) into the
   IDA 9.3 install's `plugins/` folder.

Run from an **elevated** PowerShell / Command Prompt — both steps write under
`C:\Program Files\IDA *` and need admin.

You can also target the steps individually:

```powershell
patchdiff-ai install idalib         # idapro wheel + activator only
patchdiff-ai install ida-plugins    # BinDiff/BinExport DLL copy only
```

Both accept `--ida-root <path>` to pick a specific IDA install when more than
one is discovered.

## Verifying

```powershell
patchdiff-ai health-check
```

Validates `config.json`, every tool path, and provider credentials end-to-end.

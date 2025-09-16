#!/usr/bin/env python3
import argparse
import re
import sys
from pathlib import Path
from requests_html import HTMLSession

from common import retry_on_exception, logger, resource_lock, console

SEARCH_URL = "https://www.catalog.update.microsoft.com/Search.aspx?q={}"
DL_URL = "https://catalog.update.microsoft.com/DownloadDialog.aspx"
UID_PAT = re.compile(r"goToDetails\(['\"]([0-9a-f\-]{36})['\"]\)")


def find_uid(session: HTMLSession, kb: str, product: str) -> str:
    resp = session.get(SEARCH_URL.format(kb), timeout=30)
    target = 'microsoft server operating system' if 'server' in product.lower() else product.lower()
    for a in resp.html.find("a[onclick^='goToDetails']"):
        if target in a.text.lower():
            m = UID_PAT.search(a.attrs.get("onclick", ""))
            if m:
                return m.group(1)
    raise RuntimeError("[x] UID not found")


def find_msu(session: HTMLSession, uid: str, kb: str) -> str:
    payload = {"updateIDs": f'[{{"uidInfo":"{uid}","updateID":"{uid}"}}]'}
    html = session.post(DL_URL, data=payload, timeout=30).text
    msu_re = re.compile(rf"https://[^'\"\s]*kb{kb}[^'\"\s]*\.(?:msu|cab)", re.I)
    m = msu_re.search(html)
    if not m:
        raise RuntimeError("[x] .msu link not found")
    url = m.group(0)
    return url


def grab(session: HTMLSession, url: str, out_dir: Path, overwrite: bool) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    name = url.rsplit('/', 1)[1]
    dest = out_dir / name

    with resource_lock(dest.resolve()):
        if not overwrite and dest.exists():
            console.info(f'[+] Update installer exist on disk [{name}]')
            return dest

        with session.get(url, stream=True, timeout=30) as r, dest.open("wb") as f:
            r.raise_for_status()
            console.info(f"[*] Downloading {name}")
            for chunk in r.iter_content(8192):
                if chunk:
                    f.write(chunk)

    size_mb = dest.stat().st_size // 1_048_576
    logger.info(f"[+] {name} ({size_mb} MB) downloaded to {out_dir.resolve()}")
    return dest


@retry_on_exception
def download_kb(kb, product, out_dir: Path, overwrite=False) -> Path:
    files = [f for f in out_dir.glob("*.msu") if kb in f.stem and f.is_file()]
    if len(files) == 1:
        console.info(f'[+] Update installer exist on disk [{files[0].name}]')
        return files[0]

    kb_num = kb.lower().lstrip("kb")
    session = HTMLSession()
    session.cookies.set('display-culture', 'en-US')

    uid = find_uid(session, kb, product)
    url = find_msu(session, uid, kb_num)
    dest = grab(session, url, out_dir, overwrite)
    return dest


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("kb", help="KBxxxxx or digits")
    ap.add_argument("product", help="Product substring from catalog row")
    ap.add_argument("-o", "--outdir", default=".")
    args = ap.parse_args(argv)

    download_kb(args.kb, args.product, Path(args.outdir))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[x] Interrupted")

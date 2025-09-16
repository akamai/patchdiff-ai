import os, sys, time, math, requests
from datetime import datetime, timezone

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev"
HDR = {"User-Agent": "tte/1.0", "Accept": "application/json"}
if os.getenv("NVD_API_KEY"): HDR["apiKey"] = os.getenv("NVD_API_KEY")

# ---- hard-coded date range (UTC) ----
y = 2018
START_DATE = datetime(y, 1, 1, tzinfo=timezone.utc)
END_DATE = datetime(y+1, 1, 1, tzinfo=timezone.utc)


# -------------------------------------

def pdt(s):
    if not s: return None
    s = s.strip().replace("Z", "+00:00")
    fmts = ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]
    for f in fmts:
        try:
            dt = datetime.strptime(s.split("+")[0], f)
            if "T" not in f and dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
            return dt.replace(tzinfo=timezone.utc)
        except:
            pass
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except:
        return None


def fetch():
    out = [];
    start = 0
    while True:
        r = requests.get(BASE, headers=HDR, timeout=30)
        if r.status_code != 200: raise SystemExit(f"HTTP {r.status_code}: {r.text[:200]}")
        j = r.json();
        vs = j.get("vulnerabilities", [])
        if not vs: break
        out.extend(vs);
        start += j.get("resultsPerPage", len(vs))
        if start >= j.get("totalResults", start): break
        time.sleep(0.6)
    return out


def hist(deltas, edges):
    counts = [0] * (len(edges) - 1)
    for d in deltas:
        for i in range(len(edges) - 1):
            if edges[i] <= d < edges[i + 1]: counts[i] += 1; break
    return counts


def main():
    vulns = fetch()
    deltas, zero, neg = [], [], []
    for e in vulns:
        c = e.get("cve", {})
        pub = pdt(c.get("published"))
        if not pub or not (START_DATE <= pub <= END_DATE): continue  # filter by date range
        add = pdt(c.get("cisaExploitAdd") or c.get("cisaExploitAdded"))
        if pub and add:
            dd = int(math.floor((add - pub).total_seconds() / 86400))
            deltas.append(dd)
            if dd == 0: zero.append((c.get("id"), c.get("published"), c.get("cisaExploitAdd")))
            if dd < 0:  neg.append((c.get("id"), c.get("published"), c.get("cisaExploitAdd"), dd))
    if not deltas: raise SystemExit("No parsed pairs in date range.")
    edges = [-36500, -30, -7, -1, 0, 1, 7, 30, 90, 365, 36500]
    counts = hist(deltas, edges)
    total = len(deltas)
    print(f"Filtered date range: {START_DATE.date()} – {END_DATE.date()}")
    print("Time-to-Exploit (days) = cisaExploitAdd - published")
    print(f"Parsed pairs: {total}")
    print(
        f"Zero-day: {len(zero)} ({len(zero) / total * 100:.2f}%)  Negative: {len(neg)} ({len(neg) / total * 100:.2f}%)")
    srt = sorted(deltas);
    med = srt[total // 2] if total % 2 else (srt[total // 2 - 1] + srt[total // 2]) // 2
    print(f"Median: {med}  Mean: {sum(deltas) / total:.2f}")
    print("\nHistogram:")
    mx = max(counts);
    w = 50 if mx > 50 else mx
    for a, b, cnt in zip(edges[:-1], edges[1:], counts):
        label = f"[{a},{b})".rjust(15)
        bar = "#" * (0 if mx == 0 else max(1, int(cnt * w / mx)))
        print(f"{label} {str(cnt).rjust(6)} {bar}")
    if zero:
        print("\nExamples zero-day:")
        for r in zero[:10]: print(" ", r[0], r[1], r[2])
    if neg:
        print("\nExamples negative:")
        for r in neg[:10]: print(" ", r[0], r[1], r[2], r[3])


if __name__ == "__main__": main()

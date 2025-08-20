# ShodanAPI

## shodan_targets_to_csv

Python tool to read a list of targets (IP, hostname or CIDR), query Shodan and export a CSV with one row per observed service (`IP:port`). For CIDR ranges it uses `net:CIDR` in the Shodan search API, it does **not** brute-force all IPs. By default it enriches each host with the Host API to include vulnerabilities, OS, and full service banners. It respects rate limits with retries and exponential backoff, handles transient errors and deduplicates targets.

## Requirements

- Python 3.8+
- A valid Shodan API key with access to `host` and `host/search`

You can provide the key via `--api-key` or with the environment variable `SHODAN_API_KEY`.

## Installation

No external dependencies are required. Clone or copy the script and make it executable if you want to run it directly.

```bash
chmod +x shodan_targets_to_csv.py
```

## Quick usage

Input: a `.txt` file with one target per line. Lines starting with `#` are ignored. Supported formats: IP, hostname, CIDR.

```text
# targets.txt
1.2.3.4
example.org
10.10.0.0/24
```

Basic run with default output `shodan_output.csv`:

```bash
python shodan_targets_to_csv.py -i targets.txt --api-key YOUR_KEY
```

Using the environment variable:

```bash
export SHODAN_API_KEY=YOUR_KEY
python shodan_targets_to_csv.py -i targets.txt
```

Fast mode without enrichment (uses only **Search** results, less detail but faster):

```bash
python shodan_targets_to_csv.py -i targets.txt --search-only
```

Output message on success:

```
[OK] Wrote 1234 rows to shodan_output.csv
```

## How it works

- For CIDR ranges: runs a `net:CIDR` search and collects only observed hosts from Shodan.
- For single IPs or hostnames: queries the Host API directly.
- In default mode: deduplicates discovered IPs and enriches them via Host API to include CVEs, CVSS scores, CPEs, TLS details, etc.
- In `--search-only` mode: writes rows directly from **Search** matches.

## CSV columns

The output uses camelCase headers in English. Each row corresponds to one observed service.

| Header | Description |
|---|---|
| ipAddress | IP address |
| hostnames, domains | Hostnames and domains (semicolon separated) |
| org, isp, asn, os | Organization, ISP, ASN, operating system |
| countryCode, countryName, regionName, city | Geolocation data |
| latitude, longitude | Coordinates if available |
| lastUpdate | Last update timestamp at host level |
| tagList | Shodan tags |
| port, transport | Service port and transport |
| product, version | Product name and version |
| serviceBanner | Raw service banner |
| cpeList | List of CPEs (semicolon separated) |
| vulnList | Unique CVEs (semicolon separated) |
| highestCvss | Highest CVSS score observed |
| timestamp | Service/banner timestamp |
| tlsVersion, tlsCipher | TLS version and cipher if available |
| tlsIssuerCommonName, tlsSubjectCommonName | Certificate issuer and subject CNs |

Lists are flattened with `; `. Newlines are stripped in all fields except the banner.

## Performance & limits

- Exponential backoff up to 60s on HTTP 429 (rate limits).
- Retries on network timeouts and transient errors.
- `--search-only` significantly reduces Host API calls and speeds up large CIDRs but loses some details.

## Exit codes

- `0` success
- `2` fatal error (missing args, missing API key, no valid targets)

Warnings are printed to `stderr` for hosts not found in Shodan.

## Best practices

Use this tool only for targets you are authorized to scan. Check Shodan Terms of Service and applicable law. Do not abuse rate limits.

## Examples

Export to a specific file:

```bash
python shodan_targets_to_csv.py -i scope.txt -o out.csv --api-key $SHODAN_API_KEY
```

CIDR discovery only, writing service rows directly:

```bash
python shodan_targets_to_csv.py -i cidrs.txt --search-only
```

Mixed input:

```text
# scope.txt
8.8.8.8
cloudflare.com
192.0.2.0/28
```

## Troubleshooting

- `Unauthorized`: invalid key or insufficient Shodan plan.
- `No Shodan data`: host not indexed or removed from Shodan.
- Empty CSV: check input file and ensure targets are present in Shodan.


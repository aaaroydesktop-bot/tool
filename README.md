# NetScan — Termux Networking Toolkit

A fast, scriptable network toolkit built for **Termux on Android**, with a
colourful interactive menu *and* a real command line so the same engine works
from a shell script, a cron job or a Termux widget.

```
███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
```

## Why this version is different

| | Before | Now |
|---|---|---|
| Interface | interactive menu only | menu **+ full CLI with subcommands** |
| Output | printed tables | tables, **JSON / Markdown / HTML / CSV / text** |
| Scanning | one target at a time | **batch targets, target files, watch mode with diffs** |
| Ports | fixed ranges | `top`, `web`, `db`, `remote`, `mail`, `all`, `1-1024`, `22,80,443` |
| Probing | banner read only | banners, **TLS version/cipher/fingerprint**, filtered vs closed |
| Setup | one huge install | **fast, idempotent, failure-tolerant installer** |
| Dependencies | 8 packages | 4 (and only `rich` is required to start) |
| Tests | none | 130+ unit tests plus an end-to-end CLI smoke test |

## Install (Termux)

```bash
pkg install git -y
git clone https://github.com/aaaroydesktop-bot/tool
cd tool
bash install.sh
```

The installer is safe to re-run. Useful flags:

```bash
bash install.sh --no-optional   # skip nmap/traceroute/whois/curl
bash install.sh --no-update     # skip 'pkg update'
bash install.sh --uninstall     # remove the global command
```

It finishes by running `netscan doctor`, which tells you exactly what is
available on your device.

## Quick start

```bash
netscan                                   # interactive menu
netscan scan 192.168.1.1                  # top ports on one host
netscan scan 192.168.1.1 -p 1-1024        # a range
netscan scan 10.0.0.1 10.0.0.2 -p web     # several hosts
netscan local --names                     # devices on your Wi-Fi
netscan watch 192.168.1.1 -p top --watch 60
```

Every command accepts `--json` for scripting and `-o file -f fmt` to export:

```bash
netscan scan example.com -p top --json | jq '.findings[].port'
netscan scan example.com -o report.html -f html
netscan local --names > wifi.txt
```

## Commands

| Command | What it does |
|---|---|
| `scan` | TCP port scan: banners, TLS details, closed/filtered classification |
| `local` | LAN discovery via ARP + parallel probes (works without root) |
| `ping` | latency, jitter, packet loss, TTL-based OS guess |
| `traceroute` | hop-by-hop path (uses `traceroute`, else a ping TTL walk) |
| `dns` | A/AAAA/PTR plus MX/NS/TXT when `dnsutils` is installed |
| `geo` | country/city/ISP for an IP — or your own public IP |
| `whois` | registration data via **RDAP**, with WHOIS fallbacks |
| `headers` | response headers **plus a security-header audit** |
| `subdomains` | threaded enumeration with wildcard-DNS filtering |
| `tech` | fingerprint servers, frameworks, CMS, analytics |
| `vendor` | MAC → vendor from a built-in OUI table, API as backup |
| `speedtest` | latency, jitter and download (upload with `--upload`) |
| `sysinfo` / `monitor` | CPU, RAM, storage, temperature, battery, live dashboard |
| `history` | browse, re-read and clear stored scan results |
| `plugins` | list and run plugins from `plugins/` |
| `block` / `unblock` / `firewall` | iptables/nft rules (root required, `--dry-run` supported) |
| `ask` | turn plain English into a command (`netscan ask "scan 10.0.0.1 ports 1-100"`) |
| `doctor` | diagnose Python, modules, permissions, missing tools |

Run `netscan <command> --help` for the full option list.

## Reports

Results are plain dicts, so any module can emit any format:

```bash
netscan headers example.com -o headers.md -f md
netscan scan 192.168.1.0/24 --targets-file hosts.txt -o sweep.csv -f csv
```

Formats: `json`, `md`, `html` (self-contained dark-theme report), `csv`, `txt`.
Files land in `reports/` unless you pass `-o`. Every run is also stored in
`database/toolkit.db` so `netscan history --show <id>` can replay it later.

## Exit codes

`0` success · `1` error / nothing found · `2` bad usage · `130` interrupted.

These are stable, so scripting is safe:

```bash
if netscan scan 10.0.0.5 -p 22,443 --json >/dev/null; then
    echo "host responded"
fi
```

## Plugins

Drop a `.py` file in `plugins/` that defines `run()`:

```python
def run():
    return {"hello": "world"}
```

`netscan plugins` lists what it found, `netscan plugins --run myplugin` runs one.

## Requirements

* Python 3.9+ (`pkg install python`)
* `pip install -r requirements.txt` — **only `rich` is required to start**;
  everything else is imported lazily so scans work even before pip finishes.

Optional extras unlock specific features: `nmap`, `traceroute`, `whois`,
`dnsutils`, `curl`, `termux-api` (Wi-Fi/battery details), and root for firewall
rules. `netscan doctor` reports each one.

## How it is built

```
main.py                entry point (menu + CLI dispatch)
cli.py                 argparse subcommands, output plumbing, exit codes
core/
  console.py           one shared Rich console, quiet/no-colour aware
  netutil.py           port-spec + target parsing, formatting (pure, tested)
  environment.py       Termux/root/tool detection
  report.py            report building + JSON/MD/HTML/CSV/text renderers
  http.py              shared requests session with sane defaults
  checker.py           dependency checks and the doctor report
modules/
  network/             scanner, dns, geoip, headers, subdomain, ping,
                       traceroute, speedtest, techdetect, localnet, vendor
  osint.py             WHOIS/RDAP          monitoring.py  system telemetry
  history.py           SQLite history      firewall.py    rule management
  plugins.py           plugin loader       ai.py          text -> command
  reporting.py         compatibility shim
tests/                 135 unit tests + smoke_cli.py end-to-end check
```

Design rules the code sticks to:

1. **Modules return data, never prompt.** Functions take optional arguments and
   return a report dict; the menu and the CLI both render that dict.
2. **The standard library first.** Scanning, DNS, ping, LAN discovery and
   telemetry work with no third-party packages.
3. **Degrade, do not crash.** Missing tools, no root, no termux-api: each
   feature explains itself instead of failing.
4. **One source of truth for the menu.** The interactive registry drives both
   display and dispatch, so a listed option can never be unimplemented.

## Development

```bash
python -m compileall .                   # syntax check
python -m unittest discover -s tests -t .  # unit tests
python tests/smoke_cli.py                # end-to-end CLI check
NETSCAN_DEBUG=1 netscan scan 127.0.0.1   # show tracebacks on failure
```

The test suite runs with or without `rich` installed — `tests/rich_stub.py`
provides a stand-in so the import graph and CLI wiring can be verified on a
bare interpreter.

## Legal

Only scan systems you own or have explicit permission to test. Port scanning
third parties without authorisation is illegal in most jurisdictions. You are
responsible for how you use this tool.

---

## বাংলা — দ্রুত শুরু

```bash
pkg install git -y
git clone https://github.com/aaaroydesktop-bot/tool
cd tool
bash install.sh
```

তারপর শুধু `netscan` লিখলে মেনু আসবে। কিছু দরকারি উদাহরণ:

```bash
netscan scan 192.168.1.1          # একটি হোস্ট স্ক্যান
netscan scan 192.168.1.1 -p 1-1024  # পোর্ট রেঞ্জ
netscan local --names             # আপনার Wi-Fi-এর সব ডিভাইস
netscan dns example.com           # DNS তথ্য
netscan speedtest                 # ইন্টারনেট স্পিড
netscan scan example.com -o report.html -f html   # HTML রিপোর্ট
netscan doctor                    # সমস্যা আছে কিনা পরীক্ষা
```

`netscan --help` দিলে সব কমান্ড দেখতে পাবেন।

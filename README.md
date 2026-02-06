# Kali-Codex LAN Scanner

`scanlan.py` is a lightweight CLI for local network discovery and port scanning using common tools
like `arp-scan` and `nmap`. It favors speed while offering a stealth-oriented profile for customer
security assessments.

## Requirements

- `nmap`
- `arp-scan`
- Linux with `iproute2`
- Root privileges recommended (ARP scanning and SYN scans typically require sudo)

## Usage

```bash
sudo ./scanlan.py --profile stealth
sudo ./scanlan.py --subnet 192.168.1.0/24 --ports 1-1024
sudo ./scanlan.py --json --output scan.json
```

## Profiles

- `fast`: higher rate, fewer retries
- `balanced`: default tuning
- `stealth`: slower timing and delays

## Output

By default, results print in a readable table with MAC and vendor details from `arp-scan` and open
ports from `nmap`. Use `--json` to emit machine-readable output.

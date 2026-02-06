#!/usr/bin/env python3
import argparse
import json
import shutil
import subprocess
import sys
import textwrap
import xml.etree.ElementTree as ET


def run_command(command, input_text=None):
    result = subprocess.run(
        command, input=input_text, capture_output=True, text=True
    )
    return result.returncode, result.stdout, result.stderr


def detect_default_interface():
    code, stdout, stderr = run_command(["ip", "-4", "route", "show", "default"])
    if code != 0:
        raise RuntimeError(f"Failed to read default route: {stderr.strip()}")
    for line in stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    raise RuntimeError("Could not determine default interface")


def detect_subnet():
    iface = detect_default_interface()
    code, stdout, stderr = run_command(["ip", "-4", "addr", "show", "dev", iface])
    if code != 0:
        raise RuntimeError(f"Failed to read interface address: {stderr.strip()}")
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            return line.split()[1]
    raise RuntimeError("Could not determine subnet from interface")


def parse_arp_scan(output):
    devices = {}
    for line in output.splitlines():
        if not line or line.startswith("Interface") or line.startswith("Starting"):
            continue
        if line.startswith("Ending"):
            break
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].count(".") == 3:
            ip = parts[0].strip()
            mac = parts[1].strip()
            vendor = parts[2].strip() if len(parts) > 2 else ""
            devices[ip] = {"ip": ip, "mac": mac, "vendor": vendor}
    return devices


def parse_nmap_xml(xml_text):
    root = ET.fromstring(xml_text)
    hosts = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        address = host.find("address")
        if address is None:
            continue
        ip = address.get("addr")
        ports = []
        ports_node = host.find("ports")
        if ports_node is not None:
            for port in ports_node.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                ports.append(
                    {
                        "port": int(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "service": service.get("name") if service is not None else "",
                        "product": service.get("product") if service is not None else "",
                        "version": service.get("version") if service is not None else "",
                    }
                )
        hosts[ip] = {"ip": ip, "ports": ports}
    return hosts


def build_nmap_command(args, targets):
    command = [args.nmap_path, "-sS", "-n", "-oX", "-"]
    if args.profile == "fast":
        command += ["-T4", "--max-retries", "1", "--min-rate", "200"]
    elif args.profile == "stealth":
        command += ["-T2", "--scan-delay", "50ms", "--max-retries", "3"]
    else:
        command += ["-T3", "--scan-delay", "10ms", "--max-retries", "2"]
    if args.os_detect:
        command.append("-O")
    if args.ports:
        command += ["-p", args.ports]
    elif args.top_ports:
        command += ["--top-ports", str(args.top_ports)]
    command += ["-iL", "-"]
    return command, "\n".join(targets)


def format_table(records):
    if not records:
        return "No hosts found."
    lines = []
    for record in records:
        header = f"{record['ip']}  {record.get('mac', '')}  {record.get('vendor', '')}".strip()
        lines.append(header)
        for port in record.get("ports", []):
            service = port.get("service") or ""
            detail = f"{service} {port.get('product', '')} {port.get('version', '')}".strip()
            lines.append(f"  - {port['port']}/{port['protocol']} {detail}".strip())
        lines.append("")
    return "\n".join(lines).strip()


def ensure_tool(path, name):
    if not path:
        raise RuntimeError(f"Missing required tool: {name}")


def main():
    parser = argparse.ArgumentParser(
        description="Fast, stealthy LAN scanner using arp-scan and nmap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              sudo ./scanlan.py --profile stealth
              sudo ./scanlan.py --subnet 192.168.1.0/24 --ports 1-1024
              sudo ./scanlan.py --json --output scan.json
            """
        ),
    )
    parser.add_argument("--subnet", help="CIDR subnet to scan (auto-detected if omitted)")
    parser.add_argument(
        "--profile",
        choices=["fast", "balanced", "stealth"],
        default="balanced",
        help="Scan profile tuning (default: balanced)",
    )
    parser.add_argument("--ports", help="Port range or list for nmap (overrides --top-ports)")
    parser.add_argument("--top-ports", type=int, help="Use nmap --top-ports")
    parser.add_argument("--os-detect", action="store_true", help="Enable nmap OS detection (-O)")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--output", help="Write JSON output to file")
    parser.add_argument("--nmap-path", default=shutil.which("nmap"))
    parser.add_argument("--arp-scan-path", default=shutil.which("arp-scan"))

    args = parser.parse_args()

    ensure_tool(args.nmap_path, "nmap")
    ensure_tool(args.arp_scan_path, "arp-scan")

    subnet = args.subnet or detect_subnet()

    arp_command = [args.arp_scan_path, subnet]
    code, arp_stdout, arp_stderr = run_command(arp_command)
    if code != 0:
        raise RuntimeError(f"arp-scan failed: {arp_stderr.strip()}")

    devices = parse_arp_scan(arp_stdout)
    targets = sorted(devices.keys())
    if not targets:
        targets = [subnet]

    nmap_command, nmap_input = build_nmap_command(args, targets)
    code, nmap_stdout, nmap_stderr = run_command(nmap_command, nmap_input)
    if code != 0:
        raise RuntimeError(f"nmap failed: {nmap_stderr.strip()}")

    hosts = parse_nmap_xml(nmap_stdout)

    records = []
    for ip, host in hosts.items():
        record = {"ip": ip, "ports": host.get("ports", [])}
        if ip in devices:
            record.update(devices[ip])
        records.append(record)

    records = sorted(records, key=lambda item: item["ip"])

    if args.json or args.output:
        payload = {"subnet": subnet, "hosts": records}
        output_text = json.dumps(payload, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(output_text)
        if args.json:
            print(output_text)
    else:
        print(format_table(records))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

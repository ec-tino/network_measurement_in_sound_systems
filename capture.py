"""
capture.py — tshark-based packet capture for live sound network measurement.

Three conditions supported:
    1. idle     — network not in active use
    2. live     — network under load during a live show
    3. research — controlled monitoring mode with optional node filtering

Usage examples:
    python capture.py --condition idle --interface eth0 --duration 60
    python capture.py --condition live  --interface eth0 --duration 300
    python capture.py --condition research --interface eth0 --duration 120 \
                      --nodes 192.168.1.10 192.168.1.20

Output:
    data/<condition>/capture_<timestamp>.csv
"""

import argparse
import subprocess
import sys
import os
import csv
import datetime
import json
import time

# ── tshark field names we want ─────────────────────────────────────────────
TSHARK_FIELDS = [
    "frame.time_epoch",   # absolute timestamp (seconds)
    "frame.len",          # total on-wire packet length (bytes)
    "ip.src",             # source IP address
    "ip.dst",             # destination IP address
    "ip.proto",           # protocol number (6=TCP, 17=UDP …)
    "udp.srcport",        # UDP source port
    "udp.dstport",        # UDP destination port
    "tcp.srcport",        # TCP source port
    "tcp.dstport",        # TCP destination port
]

# Common audio-protocol ports for reference (used in filtering display)
# use this to cross-reference port numbers in the capture with known audio protocols, and what the port number means
AUDIO_PROTOCOL_PORTS = {
    319:  "PTP (IEEE 1588 event)",
    320:  "PTP (IEEE 1588 general)",
    4440: "Dante audio",
    5004: "RTP audio",
    5005: "RTCP",
    6000: "CobraNet",
    8700: "AVB MAAP",
}

# write a tshark command to capture packets and writes them as .pcap file. 
# The relevant fields are then extracted from the file.
# This function is not used now. It is an alternative to build_tshark_fields_cmd 
# which directly outputs CSV fields without an intermediate pcap file.
def build_tshark_cmd(
    interface: str,
    duration: int,
    output_file: str,
    capture_filter: str = "",
    nodes: list[str] | None = None,
) -> list[str]:
    """
    Build the tshark command.

    tshark writes fields as tab-separated values (-T fields -e field …).
    We also set -E header=y so the first row is column names.
    """
    cmd = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",          # double-quote strings
        "-E", "occurrence=f",     # first value only for multi-valued fields
    ]
    

    # Add each field
    for field in TSHARK_FIELDS:
        cmd += ["-e", field]

    # Capture filter (BPF syntax) — runs in the kernel, very efficient
    if capture_filter:
        cmd += ["-f", capture_filter]
    elif nodes:
        # Build a BPF host filter covering all specified nodes
        host_exprs = " or ".join(f"host {n}" for n in nodes)
        cmd += ["-f", host_exprs]

    # Display filter (applied after capture) — optional extra layer
    # For the research condition we can further narrow in post-processing.

    cmd += ["-w", "-"]   # write raw pcap to stdout (we pipe to file separately)

    return cmd


def build_tshark_fields_cmd(
    interface: str,
    duration: int,
    nodes: list[str] | None = None,
    extra_display_filter: str = "",
) -> list[str]:
    """
    Build the simpler tshark command that directly outputs CSV fields
    (no intermediate pcap). Easier to parse, slightly less raw control.
    """
    cmd = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]

    for field in TSHARK_FIELDS:
        cmd += ["-e", field]

    # BPF capture filter
    if nodes:
        host_exprs = " or ".join(f"host {n}" for n in nodes)
        cmd += ["-f", host_exprs]

    # Wireshark display filter (post-capture, more expressive than BPF)
    if extra_display_filter:
        cmd += ["-Y", extra_display_filter]

    return cmd


def run_capture(
    interface: str,
    duration: int,
    condition: str,
    nodes: list[str] | None = None,
    extra_filter: str = "",
    output_dir: str = "data",
) -> str:
    """
    Run tshark capture and save the result as a CSV file.

    Returns:
        Path to the saved CSV file.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    condition_dir = os.path.join(output_dir, condition)
    os.makedirs(condition_dir, exist_ok=True)
    csv_path = os.path.join(condition_dir, f"capture_{timestamp}.csv")

    cmd = build_tshark_fields_cmd(
        interface=interface,
        duration=duration,
        nodes=nodes,
        extra_display_filter=extra_filter,
    )

    print(f"\n[*] Condition : {condition.upper()}")
    print(f"[*] Interface : {interface}")
    print(f"[*] Duration  : {duration}s")
    if nodes:
        print(f"[*] Nodes     : {', '.join(nodes)}")
    print(f"[*] Output    : {csv_path}")
    print(f"[*] Command   : {' '.join(cmd)}\n")
    print("[*] Capture starting … (Ctrl-C to stop early)\n")

    try:
        with open(csv_path, "w") as out_fh:
            proc = subprocess.Popen(
                cmd,
                stdout=out_fh,
                stderr=subprocess.PIPE,
                text=True,
            )
            _, stderr = proc.communicate()

        if proc.returncode not in (0, 1):   # tshark returns 1 on timeout (normal)
            print(f"[!] tshark exited with code {proc.returncode}")
            if stderr:
                print(f"[!] stderr: {stderr[:500]}")
    except FileNotFoundError:
        print("[!] tshark not found. Install with: brew install tshark")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Capture interrupted by user.")

    # Save capture metadata alongside the CSV
    meta = {
        "condition": condition,
        "interface": interface,
        "duration_s": duration,
        "nodes": nodes or [],
        "extra_filter": extra_filter,
        "timestamp": timestamp,
        "csv_file": csv_path,
        "tshark_fields": TSHARK_FIELDS,
    }
    meta_path = csv_path.replace(".csv", "_meta.json")
    with open(meta_path, "w") as mf:
        json.dump(meta, mf, indent=2)

    print(f"[✓] Saved: {csv_path}")
    print(f"[✓] Meta : {meta_path}")
    return csv_path


# ── Condition helpers ──────────────────────────────────────────────────────

def capture_idle(interface: str, duration: int, output_dir: str) -> str:
    """
    Condition 1 — Idle network.
    No filter: capture everything to get a baseline of background traffic.
    """
    return run_capture(
        interface=interface,
        duration=duration,
        condition="idle",
        output_dir=output_dir,
    )


def capture_live(interface: str, duration: int, output_dir: str) -> str:
    """
    Condition 2 — Live concert / show.
    Focus on UDP (which carries RTP/Dante audio) and multicast.
    BPF: udp — captures all UDP traffic, which includes RTP, Dante, AVB PTP.
    """
    return run_capture(
        interface=interface,
        duration=duration,
        condition="live",
        extra_filter="udp",      # Dante and RTP ride on UDP
        output_dir=output_dir,
    )


def capture_research(
    interface: str,
    duration: int,
    nodes: list[str],
    output_dir: str,
) -> str:
    """
    Condition 3 — Controlled research capture.
    Restricts capture to traffic between specified nodes.
    If no nodes are given, falls back to capturing all traffic with a
    research label for later comparison.
    """
    return run_capture(
        interface=interface,
        duration=duration,
        condition="research",
        nodes=nodes if nodes else None,
        output_dir=output_dir,
    )


# ── CLI ────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Sound network packet capture tool (tshark wrapper)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Idle baseline — 60 seconds on eth0
  python capture.py --condition idle --interface eth0 --duration 60

  # Live show — 10 minutes, UDP traffic
  python capture.py --condition live --interface eth0 --duration 600

  # Research — 2 minutes, only traffic between two known mixer nodes
  python capture.py --condition research --interface eth0 --duration 120 \\
      --nodes 192.168.1.10 192.168.1.20

  # List available interfaces
  python capture.py --list-interfaces
        """,
    )
    parser.add_argument(
        "--condition", choices=["idle", "live", "research"],
        required=False,
        help="Measurement condition",
    )
    parser.add_argument("--interface", "-i", default="eth0",
                        help="Network interface to capture on (default: eth0)")
    parser.add_argument("--duration", "-d", type=int, default=60,
                        help="Capture duration in seconds (default: 60)")
    parser.add_argument("--nodes", nargs="+", default=[],
                        help="IP addresses of nodes to filter (research mode)")
    parser.add_argument("--output-dir", default="data",
                        help="Root directory for CSV output (default: data/)")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="Print available network interfaces and exit")
    return parser.parse_args()


def list_interfaces():
    try:
        result = subprocess.run(
            ["tshark", "-D"], capture_output=True, text=True
        )
        print(result.stdout)
    except FileNotFoundError:
        print("tshark not installed.")


def main():
    args = parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    if not args.condition:
        print("Error: --condition is required. Use --help for usage.")
        sys.exit(1)

    if args.condition == "idle":
        capture_idle(args.interface, args.duration, args.output_dir)
    elif args.condition == "live":
        capture_live(args.interface, args.duration, args.output_dir)
    elif args.condition == "research":
        capture_research(args.interface, args.duration, args.nodes, args.output_dir)


if __name__ == "__main__":
    main()


# This code is generated with Claude.

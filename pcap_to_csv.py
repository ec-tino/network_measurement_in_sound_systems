"""
pcap_to_csv.py — Convert a Wireshark-saved .pcap or .pcapng file into the
same CSV format produced by capture.py, ready for use in analyze.py.

Workflow:
    1. In Wireshark UI: File → Save As → choose "Wireshark/tcpdump/... - pcap"
       or "Wireshark - pcapng" format. Save the file.
    2. Transfer the file to your project folder (scp, USB, shared folder, etc.)
    3. Run this script:

       python pcap_to_csv.py  my_capture.pcap  --condition live
       python pcap_to_csv.py  my_capture.pcapng --condition idle --output-dir data/

Output:
    data/<condition>/capture_<timestamp>.csv
    data/<condition>/capture_<timestamp>_meta.json

Requirements (install once on the remote Mac):
    pip3 install dpkt

No other dependencies beyond Python's standard library.

Supported input formats:
    .pcap    — classic libpcap format (Wireshark default "pcap" export)
    .pcapng  — next-generation pcap (Wireshark default save format)

Both are handled automatically — the script detects the format from the file
header, so the file extension doesn't matter.
"""

import argparse
import csv
import datetime
import json
import os
import socket
import struct
import sys


# ── Constants matching capture.py exactly ─────────────────────────────────

CSV_COLUMNS = [
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "udp.srcport",
    "udp.dstport",
    "tcp.srcport",
    "tcp.dstport",
]

# Protocol numbers
PROTO_TCP = 6
PROTO_UDP = 17

# Magic bytes that identify file format
PCAP_MAGIC_LE    = b'\xd4\xc3\xb2\xa1'   # little-endian classic pcap
PCAP_MAGIC_BE    = b'\xa1\xb2\xc3\xd4'   # big-endian classic pcap
PCAP_MAGIC_NS_LE = b'\x4d\x3c\xb2\xa1'   # nanosecond pcap, little-endian
PCAP_MAGIC_NS_BE = b'\xa1\xb2\x3c\x4d'   # nanosecond pcap, big-endian
PCAPNG_MAGIC     = b'\x0a\x0d\x0d\x0a'   # pcapng Section Header Block


# ══════════════════════════════════════════════════════════════════════════
#  PCAP PARSER  (classic .pcap format)
# ══════════════════════════════════════════════════════════════════════════

class PcapReader:
    """
    Minimal parser for classic pcap files (the most common Wireshark export).

    Reads the global file header to determine byte order and timestamp
    resolution, then yields (timestamp_seconds_float, raw_bytes) per packet.
    Does not depend on any third-party library — uses only Python's struct
    module to unpack binary data.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.fh = open(filepath, "rb")
        self.endian, self.nano = self._read_global_header()

    def _read_global_header(self):
        """
        Read the 24-byte global header and return (endian_char, is_nanosecond).

        The global header layout:
            Offset  Size  Field
            0       4     Magic number  (identifies format + byte order)
            4       2     Version major
            6       2     Version minor
            8       4     Timezone offset (always 0 in practice)
            12      4     Timestamp accuracy (always 0 in practice)
            16      4     Snapshot length (max bytes per packet)
            20      4     Link-layer type (1 = Ethernet, which is what we need)
        """
        magic = self.fh.read(4)
        if magic == PCAP_MAGIC_LE or magic == PCAP_MAGIC_NS_LE:
            endian = '<'   # little-endian (x86/ARM — typical Mac/PC)
            nano = (magic == PCAP_MAGIC_NS_LE)
        elif magic == PCAP_MAGIC_BE or magic == PCAP_MAGIC_NS_BE:
            endian = '>'   # big-endian (some older systems)
            nano = (magic == PCAP_MAGIC_NS_BE)
        else:
            raise ValueError(
                f"Not a valid pcap file (bad magic bytes: {magic.hex()}). "
                "Make sure you saved as pcap or pcapng from Wireshark."
            )
        # Read remaining 20 bytes of global header (we only need link type)
        self.fh.read(20)
        return endian, nano

    def __iter__(self):
        """
        Yield (timestamp_float, raw_packet_bytes) for each packet record.

        Each packet record has a 16-byte header:
            Offset  Size  Field
            0       4     Timestamp seconds
            4       4     Timestamp microseconds (or nanoseconds)
            8       4     Captured length (bytes actually saved)
            12      4     Original length (bytes on wire — what we want)

        We use the original length as frame.len, matching tshark behaviour.
        """
        fmt = f"{self.endian}IIII"   # four unsigned 32-bit ints
        hdr_size = struct.calcsize(fmt)

        while True:
            raw_hdr = self.fh.read(hdr_size)
            if len(raw_hdr) < hdr_size:
                break   # end of file

            ts_sec, ts_sub, cap_len, orig_len = struct.unpack(fmt, raw_hdr)

            # Convert sub-second part to fractional seconds
            if self.nano:
                ts = ts_sec + ts_sub / 1_000_000_000
            else:
                ts = ts_sec + ts_sub / 1_000_000

            raw_packet = self.fh.read(cap_len)
            if len(raw_packet) < cap_len:
                break   # truncated file

            yield ts, orig_len, raw_packet

    def close(self):
        self.fh.close()


# ══════════════════════════════════════════════════════════════════════════
#  PCAPNG PARSER  (.pcapng format — Wireshark's default save format)
# ══════════════════════════════════════════════════════════════════════════

class PcapngReader:
    """
    Minimal parser for pcapng files.

    pcapng is block-based. Each block starts with a 4-byte block type and
    4-byte total block length, followed by block-specific data, followed by
    another copy of the block length.

    We only need two block types:
        0x0A0D0D0A — Section Header Block (SHB): tells us byte order
        0x00000001 — Interface Description Block (IDB): tells us timestamp resolution
        0x00000006 — Enhanced Packet Block (EPB): actual packet data (most common)
        0x00000003 — Obsolete Packet Block (OPB): older packet format, also handled
        0x00000002 — Simple Packet Block (SPB): rare, handled as fallback
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.fh = open(filepath, "rb")
        self.endian = '<'           # default; updated from SHB
        self.if_tsresol = {}        # interface_id → timestamp resolution (seconds per unit)
        self._read_shb()

    def _read_shb(self):
        """
        Read the Section Header Block to determine byte order.

        The SHB Byte-Order Magic field always stores the value 0x1A2B3C4D.
        We first try reading it as little-endian. If the result equals
        0x1A2B3C4D the file is little-endian; if it equals 0x4D3C2B1A the
        file is big-endian. Comparing raw bytes is NOT reliable because the
        byte sequence [4D 3C 2B 1A] is the little-endian encoding of
        0x1A2B3C4D, which looks like the big-endian encoding on the wire.
        """
        self.fh.read(4)  # block type (0x0A0D0D0A — already verified by open_pcap)
        # Read block length using LE first (works for both; we only need it to skip)
        block_len_bytes = self.fh.read(4)
        bom_bytes = self.fh.read(4)

        # Interpret BOM as a little-endian uint32 and compare to the magic value
        bom_as_le = struct.unpack('<I', bom_bytes)[0]
        if bom_as_le == 0x1A2B3C4D:
            self.endian = '<'   # little-endian (most common — x86/ARM Mac)
        else:
            self.endian = '>'   # big-endian

        # Now we know endianness — re-read block_len correctly to skip the rest
        block_len = struct.unpack(f'{self.endian}I', block_len_bytes)[0]
        # Already read 12 bytes (type=4 + len=4 + bom=4); skip to end of SHB
        # SHB also has: version_major(2) + version_minor(2) + section_len(8) + options
        self.fh.read(block_len - 12)

    def _parse_options(self, data: bytes) -> dict:
        """
        Parse pcapng option fields from a byte string.
        Options are TLV-encoded: 2-byte code, 2-byte length, N-byte value.
        We only look for option code 9 (if_tsresol) in IDB blocks.
        """
        opts = {}
        pos = 0
        e = self.endian
        while pos + 4 <= len(data):
            code, length = struct.unpack_from(f'{e}HH', data, pos)
            pos += 4
            if code == 0:     # end of options
                break
            value = data[pos:pos + length]
            opts[code] = value
            # Pad to 4-byte boundary
            pos += length + (4 - length % 4) % 4
        return opts

    def _read_idb(self, block_data: bytes):
        """
        Parse Interface Description Block and store its timestamp resolution.

        By default pcapng timestamps are in microseconds (resolution = 1e-6).
        Option code 9 (if_tsresol) overrides this:
            - if bit 7 is 0: resolution = 10^(-value)
            - if bit 7 is 1: resolution = 2^(-(value & 0x7F))
        """
        if_id = len(self.if_tsresol)   # interfaces are numbered in order
        tsresol = 1e-6                  # default: microseconds

        opts = self._parse_options(block_data[4:])  # skip link type + reserved
        if 9 in opts:                   # if_tsresol option present
            byte = opts[9][0]
            if byte & 0x80:
                tsresol = 2 ** -(byte & 0x7F)
            else:
                tsresol = 10 ** -byte

        self.if_tsresol[if_id] = tsresol

    def __iter__(self):
        """Yield (timestamp_float, orig_len, raw_packet_bytes) per packet."""
        e = self.endian

        while True:
            # Read block type + length (8 bytes)
            hdr = self.fh.read(8)
            if len(hdr) < 8:
                break

            block_type, block_len = struct.unpack_from(f'{e}II', hdr)
            # Remaining body = block_len - 12 (type + len + trailing len fields)
            body_len = block_len - 12
            if body_len < 0:
                break
            body = self.fh.read(body_len)
            self.fh.read(4)   # trailing block length (redundant, skip)

            if len(body) < body_len:
                break

            # ── Section Header Block — re-parse for byte order changes
            if block_type == 0x0A0D0D0A:
                bom_as_le = struct.unpack_from('<I', body, 0)[0]
                self.endian = '<' if bom_as_le == 0x1A2B3C4D else '>'
                e = self.endian
                continue

            # ── Interface Description Block
            if block_type == 0x00000001:
                self._read_idb(body)
                continue

            # ── Enhanced Packet Block (the main packet format in modern pcapng)
            if block_type == 0x00000006:
                if len(body) < 20:
                    continue
                if_id = struct.unpack_from(f'{e}I', body, 0)[0]
                ts_high = struct.unpack_from(f'{e}I', body, 4)[0]
                ts_low  = struct.unpack_from(f'{e}I', body, 8)[0]
                cap_len = struct.unpack_from(f'{e}I', body, 12)[0]
                orig_len = struct.unpack_from(f'{e}I', body, 16)[0]
                raw_packet = body[20:20 + cap_len]

                tsresol = self.if_tsresol.get(if_id, 1e-6)
                ts_raw = (ts_high << 32) | ts_low
                ts = ts_raw * tsresol
                yield ts, orig_len, raw_packet
                continue

            # ── Obsolete Packet Block (older pcapng files)
            if block_type == 0x00000003:
                if len(body) < 20:
                    continue
                if_id = struct.unpack_from(f'{e}H', body, 0)[0]
                ts_high = struct.unpack_from(f'{e}H', body, 2)[0]
                ts_low  = struct.unpack_from(f'{e}I', body, 4)[0]
                cap_len = struct.unpack_from(f'{e}I', body, 8)[0]
                orig_len = struct.unpack_from(f'{e}I', body, 12)[0]
                raw_packet = body[16:16 + cap_len]

                tsresol = self.if_tsresol.get(if_id, 1e-6)
                ts_raw = (ts_high << 32) | ts_low
                ts = ts_raw * tsresol
                yield ts, orig_len, raw_packet
                continue

            # ── Simple Packet Block (rare, no timestamp — skip)
            # All other block types are metadata — safely ignored

    def close(self):
        self.fh.close()


# ══════════════════════════════════════════════════════════════════════════
#  FORMAT DETECTION
# ══════════════════════════════════════════════════════════════════════════

def open_pcap(filepath: str):
    """
    Detect whether the file is classic pcap or pcapng and return the
    appropriate reader object.

    Detection is based on the first 4 bytes (magic number), not the
    file extension — so it works even if the file was saved with the
    wrong extension.
    """
    with open(filepath, "rb") as f:
        magic = f.read(4)

    if magic == PCAPNG_MAGIC:
        return PcapngReader(filepath)
    elif magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
        return PcapReader(filepath)
    else:
        raise ValueError(
            f"Unrecognized file format (magic: {magic.hex()}).\n"
            "In Wireshark: File → Save As → select 'Wireshark/tcpdump/... - pcap' "
            "or 'Wireshark - pcapng' from the format dropdown."
        )


# ══════════════════════════════════════════════════════════════════════════
#  PACKET DISSECTOR  (Ethernet → IP → TCP/UDP field extraction)
# ══════════════════════════════════════════════════════════════════════════

def parse_ethernet(raw: bytes) -> dict:
    """
    Extract the fields we need from a raw Ethernet frame.

    Returns a dict with keys matching CSV_COLUMNS. Fields that aren't
    applicable for this packet are set to empty string "".

    Ethernet frame layout:
        Offset  Size  Field
        0       6     Destination MAC
        6       6     Source MAC
        12      2     EtherType  (0x0800 = IPv4, 0x8100 = VLAN-tagged)

    IPv4 header layout (minimum 20 bytes):
        Offset  Size  Field
        0       1     Version (4 bits) + IHL (4 bits)
        1       1     DSCP/ECN
        2       2     Total length
        4       2     Identification
        6       2     Flags + Fragment offset
        8       1     TTL
        9       1     Protocol  (6=TCP, 17=UDP)
        10      2     Header checksum
        12      4     Source IP
        16      4     Destination IP
        20+          Options (if IHL > 5), then payload

    UDP header layout (8 bytes):
        0       2     Source port
        2       2     Destination port
        4       2     Length
        6       2     Checksum

    TCP header layout (minimum 20 bytes):
        0       2     Source port
        2       2     Destination port
        4       4     Sequence number
        8       4     Acknowledgment number
        12      1     Data offset (4 bits) + reserved
        13      1     Flags
        14      2     Window size
        16      2     Checksum
        18      2     Urgent pointer
    """
    row = {col: "" for col in CSV_COLUMNS}  # start with all fields empty

    # ── Need at least 14 bytes for Ethernet header
    if len(raw) < 14:
        return row

    ethertype = struct.unpack_from('>H', raw, 12)[0]

    # ── Handle 802.1Q VLAN tags (common on managed audio switches)
    ip_offset = 14
    if ethertype == 0x8100:   # single VLAN tag
        if len(raw) < 18:
            return row
        ethertype = struct.unpack_from('>H', raw, 16)[0]
        ip_offset = 18
    elif ethertype == 0x88A8:  # double-tagged (QinQ, rare)
        if len(raw) < 22:
            return row
        ethertype = struct.unpack_from('>H', raw, 20)[0]
        ip_offset = 22

    # ── Only process IPv4 (EtherType 0x0800)
    # IPv6 (0x86DD), ARP (0x0806), etc. get empty IP fields — that's correct
    if ethertype != 0x0800:
        return row

    # ── IPv4 header
    if len(raw) < ip_offset + 20:
        return row

    ip_byte0 = raw[ip_offset]
    ip_ihl = (ip_byte0 & 0x0F) * 4   # header length in bytes (IHL field × 4)
    ip_proto = raw[ip_offset + 9]
    ip_src = socket.inet_ntoa(raw[ip_offset + 12: ip_offset + 16])
    ip_dst = socket.inet_ntoa(raw[ip_offset + 16: ip_offset + 20])

    row["ip.src"]   = ip_src
    row["ip.dst"]   = ip_dst
    row["ip.proto"] = str(ip_proto)

    transport_offset = ip_offset + ip_ihl

    # ── UDP
    if ip_proto == PROTO_UDP:
        if len(raw) >= transport_offset + 8:
            udp_sport = struct.unpack_from('>H', raw, transport_offset)[0]
            udp_dport = struct.unpack_from('>H', raw, transport_offset + 2)[0]
            row["udp.srcport"] = str(udp_sport)
            row["udp.dstport"] = str(udp_dport)

    # ── TCP
    elif ip_proto == PROTO_TCP:
        if len(raw) >= transport_offset + 4:
            tcp_sport = struct.unpack_from('>H', raw, transport_offset)[0]
            tcp_dport = struct.unpack_from('>H', raw, transport_offset + 2)[0]
            row["tcp.srcport"] = str(tcp_sport)
            row["tcp.dstport"] = str(tcp_dport)

    return row


# ══════════════════════════════════════════════════════════════════════════
#  MAIN CONVERTER
# ══════════════════════════════════════════════════════════════════════════

def convert(
    input_path: str,
    condition: str,
    output_dir: str = "data",
    show_progress: bool = True,
) -> str:
    """
    Read a pcap/pcapng file and write a CSV + metadata JSON in the same
    format as capture.py output.

    Parameters:
        input_path   — path to the .pcap or .pcapng file from Wireshark
        condition    — one of "idle", "live", "research" (your choice)
        output_dir   — root folder for output (default: "data/")
        show_progress — print a progress counter every 10,000 packets

    Returns:
        Path to the written CSV file.
    """
    # ── Set up output paths
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    cond_dir = os.path.join(output_dir, condition)
    os.makedirs(cond_dir, exist_ok=True)
    csv_path = os.path.join(cond_dir, f"capture_{timestamp}.csv")
    meta_path = csv_path.replace(".csv", "_meta.json")

    # ── Open the pcap file
    print(f"\n[*] Input  : {input_path}")
    print(f"[*] Format : detecting …", end="", flush=True)
    try:
        reader = open_pcap(input_path)
    except (ValueError, FileNotFoundError) as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

    fmt_name = "pcapng" if isinstance(reader, PcapngReader) else "pcap"
    print(f" {fmt_name}")
    print(f"[*] Condition : {condition.upper()}")
    print(f"[*] Output    : {csv_path}")
    print(f"[*] Converting …\n")

    # ── Write CSV
    packet_count = 0
    first_ts = None
    last_ts = None
    skipped = 0

    with open(csv_path, "w", newline="") as csv_fh:
        writer = csv.DictWriter(csv_fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for ts, orig_len, raw_packet in reader:
            if first_ts is None:
                first_ts = ts
            last_ts = ts

            # Parse Ethernet/IP/TCP/UDP fields
            row = parse_ethernet(raw_packet)

            # frame.time_epoch and frame.len always come from the pcap record,
            # not from inside the packet payload
            row["frame.time_epoch"] = f"{ts:.6f}"
            row["frame.len"] = str(orig_len)

            writer.writerow(row)
            packet_count += 1

            if show_progress and packet_count % 10_000 == 0:
                print(f"  … {packet_count:,} packets processed", end="\r", flush=True)

    reader.close()

    if packet_count == 0:
        print("[!] Warning: no packets were written. Check that the file "
              "contains Ethernet (linktype 1) traffic.")
    else:
        print(f"  … {packet_count:,} packets processed")

    # ── Write metadata JSON (same schema as capture.py)
    duration_s = round(last_ts - first_ts, 3) if (first_ts and last_ts) else 0
    meta = {
        "condition": condition,
        "interface": "wireshark-export",
        "duration_s": duration_s,
        "nodes": [],
        "extra_filter": "",
        "timestamp": timestamp,
        "csv_file": csv_path,
        "tshark_fields": CSV_COLUMNS,
        "source_file": os.path.basename(input_path),
        "source_format": fmt_name,
        "total_packets": packet_count,
        "note": "Converted from Wireshark pcap export via pcap_to_csv.py",
    }
    with open(meta_path, "w") as mf:
        json.dump(meta, mf, indent=2)

    # ── Print summary
    print(f"\n{'='*55}")
    print(f"  Conversion complete")
    print(f"{'='*55}")
    print(f"  Packets written : {packet_count:,}")
    print(f"  Duration        : {duration_s:.1f} s")
    print(f"  CSV             : {csv_path}")
    print(f"  Metadata        : {meta_path}")
    print(f"{'='*55}")
    print(f"\n  Next step — run the analyzer:")
    print(f"  python analysis/analyze.py {csv_path}\n")

    return csv_path


# ══════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="Convert a Wireshark .pcap/.pcapng file to the project CSV format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
How to save from Wireshark UI:
  1. Capture packets using the Wireshark GUI as normal.
  2. File → Save As
  3. In the format dropdown, choose one of:
       • "Wireshark/tcpdump/... - pcap"    → saves as .pcap  (recommended)
       • "Wireshark - pcapng"              → saves as .pcapng (also fine)
  4. Save the file somewhere accessible.
  5. Run this script on that file.

Examples:
  python pcap_to_csv.py  captures/idle_session.pcap    --condition idle
  python pcap_to_csv.py  captures/show_night1.pcapng   --condition live
  python pcap_to_csv.py  research_run1.pcap             --condition research --output-dir data/
        """,
    )
    parser.add_argument(
        "input",
        help="Path to the .pcap or .pcapng file exported from Wireshark",
    )
    parser.add_argument(
        "--condition", "-c",
        choices=["idle", "live", "research"],
        required=True,
        help="Which measurement condition this capture represents",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="data",
        help="Root folder for CSV output (default: data/). "
             "A subfolder named after the condition is created inside it.",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not os.path.exists(args.input):
        print(f"[!] File not found: {args.input}")
        sys.exit(1)

    convert(
        input_path=args.input,
        condition=args.condition,
        output_dir=args.output_dir,
        show_progress=not args.quiet,
    )


if __name__ == "__main__":
    main()


## CODE GENERATED WITH CLAUDE
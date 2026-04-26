"""
device_analysis.py — Identify devices on the sound network and map how
they communicate with each other.

Reads a .pcap or .pcapng file directly (no CSV step needed) and produces:
    • A device inventory — every unique device with its IP, MAC, vendor,
      and inferred device type (console, amp, mic system, etc.)
    • A communication matrix — packet count, byte volume, and protocol
      for every pair of devices that exchanged traffic
    • Traffic rankings — who sends most, who receives most
    • A heatmap showing the communication intensity between devices
    • A network graph showing which devices talk to which
    • A plain-text report of all findings

Usage:
    python device_analysis.py  captures/my_capture.pcapng
    python device_analysis.py  captures/my_capture.pcapng  --condition live
    python device_analysis.py  captures/my_capture.pcap    --output-dir reports/

Requirements (install once):
    pip3 install matplotlib pandas numpy seaborn
"""

import argparse
import csv
import datetime
import json
import os
import socket
import struct
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
import numpy as np
import pandas as pd
import seaborn as sns


# ══════════════════════════════════════════════════════════════════════════
#  OUI DATABASE  — MAC prefix → manufacturer + device type hint
#  Sources: IEEE public registry, Wireshark manuf file, pro-audio knowledge
# ══════════════════════════════════════════════════════════════════════════

OUI_DB = {
    # ── Allen & Heath (digital mixers, stage boxes) ───────────────────────
    "00:04:C4": ("Allen & Heath",  "Digital Mixer / Stage Box"),
    "18:C3:F4": ("Allen & Heath",  "Digital Mixer / Stage Box"),

    # ── Shure (wireless mic systems, IEM, networked audio) ────────────────
    "00:0C:1E": ("Shure",          "Wireless Mic / IEM System"),
    "00:1B:66": ("Shure",          "Wireless Mic / IEM System"),
    "D4:20:00": ("Shure",          "Wireless Mic / IEM System"),
    "00:0F:A3": ("Shure",          "Wireless Mic / IEM System"),

    # ── QSC (amplifiers, Q-SYS platform) ─────────────────────────────────
    "00:60:74": ("QSC Audio",      "Amplifier / Q-SYS Core"),
    "5C:A1:3C": ("QSC Audio",      "Amplifier / Q-SYS Core"),
    "00:1E:70": ("QSC Audio",      "Amplifier / Q-SYS Core"),

    # ── Audinate (Dante protocol — appears on many brands) ────────────────
    "00:1D:C1": ("Audinate",       "Dante-enabled Device"),
    "00:1A:B6": ("Audinate",       "Dante-enabled Device"),

    # ── MUSIC Group / Midas / Behringer / Klark Teknik ────────────────────
    "48:0B:B2": ("Midas / Behringer / MUSIC Group", "Digital Mixer / Stage Box"),
    "00:1C:2C": ("MUSIC Group",    "Digital Mixer / Stage Box"),

    # ── Yamaha (digital mixers, routers, amplifiers) ──────────────────────
    "00:A0:DE": ("Yamaha",         "Digital Mixer / Network Amp"),
    "00:17:B7": ("Yamaha",         "Digital Mixer / Network Amp"),

    # ── DiGiCo (digital mixing consoles) ──────────────────────────────────
    "00:1B:F8": ("DiGiCo",         "Digital Mixing Console"),

    # ── Focusrite (RedNet, Dante interfaces) ──────────────────────────────
    "00:02:A9": ("Focusrite",      "Audio Interface / RedNet"),
    "00:21:9B": ("Focusrite",      "Audio Interface / RedNet"),
    "70:B3:D5": ("Focusrite",      "Audio Interface / RedNet"),

    # ── Avid (Pro Tools, S-Series, Stage64) ───────────────────────────────
    "00:1C:17": ("Avid Technology","Pro Tools / S-Series Console"),
    "00:C0:5B": ("Avid Technology","Pro Tools / S-Series Console"),

    # ── Crown / Harman (network amplifiers) ───────────────────────────────
    "00:17:F2": ("Crown / Harman", "Network Amplifier"),
    "00:26:86": ("Harman",         "Network Amplifier"),

    # ── d&b Audiotechnik (amplifiers) ─────────────────────────────────────
    "00:1A:CA": ("d&b Audiotechnik","Amplifier"),

    # ── Lab.gruppen ───────────────────────────────────────────────────────
    "00:40:9D": ("Lab.gruppen",    "Amplifier"),

    # ── Meyer Sound ───────────────────────────────────────────────────────
    "00:50:C2": ("Meyer Sound",    "Loudspeaker System"),

    # ── Sennheiser (wireless systems, monitoring) ─────────────────────────
    "00:1D:29": ("Sennheiser",     "Wireless Mic / IEM System"),
    "48:3E:DB": ("Sennheiser",     "Wireless Mic / IEM System"),

    # ── BSS Audio / Soundcraft / Studer ───────────────────────────────────
    "00:60:56": ("BSS / Soundcraft","Digital Mixer / Signal Processor"),

    # ── Biamp Systems (signal processors) ────────────────────────────────
    "00:0F:E2": ("Biamp Systems",  "Signal Processor / DSP"),

    # ── Roland (stage performers, V-Mixers) ───────────────────────────────
    "00:0A:92": ("Roland",         "Digital Mixer / Stage Unit"),

    # ── Apple (laptops running control software) ──────────────────────────
    "EC:67:94": ("Apple",          "Laptop / Control Computer"),
    "00:1C:B3": ("Apple",          "Laptop / Control Computer"),
    "5C:F9:38": ("Apple",          "Laptop / Control Computer"),
    "A4:C3:F0": ("Apple",          "Laptop / Control Computer"),
    "F0:18:98": ("Apple",          "Laptop / Control Computer"),

    # ── Realtek (embedded NIC — present in many audio devices) ───────────
    "00:E0:4C": ("Realtek NIC",    "Network Device (embedded NIC)"),

    # ── Cisco / managed switches ──────────────────────────────────────────
    "00:00:0C": ("Cisco",          "Network Switch / Router"),
    "00:1E:BD": ("Cisco",          "Network Switch / Router"),

    # ── Raspberry Pi (research nodes) ─────────────────────────────────────
    "B8:27:EB": ("Raspberry Pi",   "Research / Monitoring Node"),
    "DC:A6:32": ("Raspberry Pi",   "Research / Monitoring Node"),
}

# Known audio-network UDP ports for protocol labeling
PORT_LABELS = {
    319:  "PTP-Event",
    320:  "PTP-General",
    4440: "Dante",
    5004: "RTP",
    5005: "RTCP",
    5353: "mDNS",
    6000: "CobraNet",
    8708: "AVB/AVTP",
    8709: "AVB/AVTP",
    9131: "AVB-MAAP",
    17221:"AEM (AVB control)",
    17220:"AEM (AVB control)",
}

# Vendor → human-readable device category
VENDOR_CATEGORY = {
    "Allen & Heath":  "🎛  Mixer / Stage Box",
    "Shure":          "🎤  Wireless Mic / IEM",
    "QSC Audio":      "🔊  Amplifier / DSP",
    "Audinate":       "🎵  Dante Network Device",
    "Midas / Behringer / MUSIC Group": "🎛  Mixer / Stage Box",
    "Apple":          "💻  Control Computer",
    "Realtek NIC":    "🔌  Network Device",
    "DiGiCo":         "🎛  Digital Console",
    "Yamaha":         "🎛  Mixer / Amplifier",
    "Focusrite":      "🎵  Audio Interface",
    "Avid Technology":"🎛  Pro Tools Console",
    "Crown / Harman": "🔊  Amplifier",
    "d&b Audiotechnik":"🔊  Amplifier",
    "Sennheiser":     "🎤  Wireless Mic / IEM",
    "Cisco":          "🔀  Network Switch",
    "Raspberry Pi":   "🔬  Research Node",
}

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}
MULTICAST_PREFIXES = ("224.", "225.", "226.", "239.", "ff")


# ══════════════════════════════════════════════════════════════════════════
#  PCAP / PCAPNG READER  (same core as pcap_to_csv.py)
# ══════════════════════════════════════════════════════════════════════════

PCAP_MAGIC_LE    = b'\xd4\xc3\xb2\xa1'
PCAP_MAGIC_BE    = b'\xa1\xb2\xc3\xd4'
PCAP_MAGIC_NS_LE = b'\x4d\x3c\xb2\xa1'
PCAP_MAGIC_NS_BE = b'\xa1\xb2\x3c\x4d'
PCAPNG_MAGIC     = b'\x0a\x0d\x0d\x0a'


class PcapReader:
    def __init__(self, filepath):
        self.fh = open(filepath, "rb")
        magic = self.fh.read(4)
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            self.endian = '<'
            self.nano = (magic == PCAP_MAGIC_NS_LE)
        else:
            self.endian = '>'
            self.nano = (magic == PCAP_MAGIC_NS_BE)
        self.fh.read(20)  # skip rest of global header

    def __iter__(self):
        fmt = f"{self.endian}IIII"
        sz = struct.calcsize(fmt)
        while True:
            raw = self.fh.read(sz)
            if len(raw) < sz: break
            ts_sec, ts_sub, cap_len, orig_len = struct.unpack(fmt, raw)
            ts = ts_sec + ts_sub / (1e9 if self.nano else 1e6)
            pkt = self.fh.read(cap_len)
            if len(pkt) < cap_len: break
            yield ts, orig_len, pkt

    def close(self): self.fh.close()


class PcapngReader:
    def __init__(self, filepath):
        self.fh = open(filepath, "rb")
        self.endian = '<'
        self.if_tsresol = {}
        self._read_shb()

    def _read_shb(self):
        self.fh.read(4)                          # block type
        block_len_bytes = self.fh.read(4)
        bom_bytes = self.fh.read(4)
        bom_as_le = struct.unpack('<I', bom_bytes)[0]
        self.endian = '<' if bom_as_le == 0x1A2B3C4D else '>'
        block_len = struct.unpack(f'{self.endian}I', block_len_bytes)[0]
        self.fh.read(block_len - 12)

    def _parse_options(self, data):
        opts, pos, e = {}, 0, self.endian
        while pos + 4 <= len(data):
            code, length = struct.unpack_from(f'{e}HH', data, pos)
            pos += 4
            if code == 0: break
            opts[code] = data[pos:pos + length]
            pos += length + (4 - length % 4) % 4
        return opts

    def _read_idb(self, body):
        if_id = len(self.if_tsresol)
        tsresol = 1e-6
        opts = self._parse_options(body[4:])
        if 9 in opts:
            b = opts[9][0]
            tsresol = 2 ** -(b & 0x7F) if (b & 0x80) else 10 ** -b
        self.if_tsresol[if_id] = tsresol

    def __iter__(self):
        e = self.endian
        while True:
            hdr = self.fh.read(8)
            if len(hdr) < 8: break
            btype, blen = struct.unpack_from(f'{e}II', hdr)
            body_len = blen - 12
            if body_len < 0: break
            body = self.fh.read(body_len)
            self.fh.read(4)
            if len(body) < body_len: break

            if btype == 0x0A0D0D0A:
                bom_as_le = struct.unpack_from('<I', body, 0)[0]
                self.endian = '<' if bom_as_le == 0x1A2B3C4D else '>'
                e = self.endian
            elif btype == 0x00000001:
                self._read_idb(body)
            elif btype in (0x00000006, 0x00000003):
                if len(body) < 20: continue
                if_id    = struct.unpack_from(f'{e}I', body, 0)[0]
                ts_high  = struct.unpack_from(f'{e}I', body, 4)[0]
                ts_low   = struct.unpack_from(f'{e}I', body, 8)[0]
                cap_len  = struct.unpack_from(f'{e}I', body, 12)[0]
                orig_len = struct.unpack_from(f'{e}I', body, 16)[0]
                pkt      = body[20:20 + cap_len]
                tsresol  = self.if_tsresol.get(if_id, 1e-6)
                ts       = ((ts_high << 32) | ts_low) * tsresol
                yield ts, orig_len, pkt

    def close(self): self.fh.close()


def open_pcap(filepath):
    with open(filepath, "rb") as f:
        magic = f.read(4)
    if magic == PCAPNG_MAGIC:
        return PcapngReader(filepath)
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
        return PcapReader(filepath)
    raise ValueError(f"Not a recognized pcap/pcapng file (magic: {magic.hex()})")


# ══════════════════════════════════════════════════════════════════════════
#  PACKET DISSECTOR
# ══════════════════════════════════════════════════════════════════════════

def dissect(orig_len, raw):
    """
    Parse an Ethernet frame and return a flat dict of fields.
    Returns None for non-Ethernet or malformed frames.
    """
    if len(raw) < 14:
        return None

    dst_mac = raw[0:6].hex(':')
    src_mac = raw[6:12].hex(':')
    etype   = struct.unpack_from('>H', raw, 12)[0]

    # Strip VLAN tags
    ip_offset = 14
    if etype == 0x8100:
        if len(raw) < 18: return None
        etype = struct.unpack_from('>H', raw, 16)[0]
        ip_offset = 18
    elif etype == 0x88A8:
        if len(raw) < 22: return None
        etype = struct.unpack_from('>H', raw, 20)[0]
        ip_offset = 22

    pkt = {
        "orig_len": orig_len,
        "src_mac":  src_mac,
        "dst_mac":  dst_mac,
        "etype":    etype,
        "src_ip":   None,
        "dst_ip":   None,
        "proto":    None,
        "src_port": None,
        "dst_port": None,
    }

    # IPv4 only
    if etype != 0x0800:
        return pkt
    if len(raw) < ip_offset + 20:
        return pkt

    ihl   = (raw[ip_offset] & 0x0F) * 4
    proto = raw[ip_offset + 9]
    src_ip = socket.inet_ntoa(raw[ip_offset + 12: ip_offset + 16])
    dst_ip = socket.inet_ntoa(raw[ip_offset + 16: ip_offset + 20])

    pkt["src_ip"] = src_ip
    pkt["dst_ip"] = dst_ip
    pkt["proto"]  = proto

    t_off = ip_offset + ihl
    if proto == 17 and len(raw) >= t_off + 4:   # UDP
        pkt["src_port"] = struct.unpack_from('>H', raw, t_off)[0]
        pkt["dst_port"] = struct.unpack_from('>H', raw, t_off + 2)[0]
    elif proto == 6 and len(raw) >= t_off + 4:  # TCP
        pkt["src_port"] = struct.unpack_from('>H', raw, t_off)[0]
        pkt["dst_port"] = struct.unpack_from('>H', raw, t_off + 2)[0]

    return pkt


# ══════════════════════════════════════════════════════════════════════════
#  VENDOR / DEVICE IDENTIFICATION
# ══════════════════════════════════════════════════════════════════════════

def lookup_vendor(mac: str):
    """Return (vendor_name, device_type_hint) for a MAC address."""
    oui = mac[:8].upper()
    if oui in OUI_DB:
        return OUI_DB[oui]
    return ("Unknown", "Unknown Device")


def infer_device_type(vendor: str, ports_seen: set) -> str:
    """
    Refine the device type by combining vendor info with ports observed.
    For example, a Shure device sending on port 8708 is likely a
    wireless receiver streaming AVB audio rather than just advertising.
    """
    cat = VENDOR_CATEGORY.get(vendor, "❓  Unknown Device")

    # Port-based refinements
    if 8708 in ports_seen or 8709 in ports_seen:
        if "Shure" in vendor:
            return "🎤  Shure Wireless (AVB stream)"
        if "QSC" in vendor:
            return "🔊  QSC Amplifier (AVB stream)"
        if "Allen" in vendor:
            return "🎛  Allen & Heath (AVB stream)"
    if 4440 in ports_seen:
        return cat.split("  ")[0] + "  " + vendor + " (Dante stream)"
    if 5353 in ports_seen and "Apple" in vendor:
        return "💻  Apple (mDNS / Control Software)"

    return cat


def is_multicast(ip: str) -> bool:
    if ip is None: return False
    return (ip.startswith(("224.", "225.", "226.", "239.")) or
            ip == "255.255.255.255")


# ══════════════════════════════════════════════════════════════════════════
#  ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════════════════

def analyze(filepath: str, condition: str = "unknown", output_dir: str = "reports"):
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n[*] Reading: {filepath}")
    reader = open_pcap(filepath)

    # ── Pass 1: collect all raw packet data ─────────────────────────────
    packets = []
    for ts, orig_len, raw in reader:
        p = dissect(orig_len, raw)
        if p:
            p["ts"] = ts
            packets.append(p)
    reader.close()
    print(f"[*] Parsed {len(packets):,} packets")

    if not packets:
        print("[!] No packets to analyze.")
        return

    # ── Build device registry ────────────────────────────────────────────
    # Key = MAC address (most reliable unique identifier at L2)
    devices = {}   # mac → {ip, vendor, device_type, ports_seen, ...}

    for p in packets:
        for role in ("src", "dst"):
            mac = p[f"{role}_mac"]
            ip  = p[f"{role}_ip"]

            # Skip multicast MACs (broadcast/group addresses)
            if int(mac.split(':')[0], 16) & 0x01:
                continue

            if mac not in devices:
                vendor, dtype = lookup_vendor(mac)
                devices[mac] = {
                    "mac":         mac,
                    "ip":          None,
                    "vendor":      vendor,
                    "device_type": dtype,
                    "ports_seen":  set(),
                    "pkts_sent":   0,
                    "pkts_recv":   0,
                    "bytes_sent":  0,
                    "bytes_recv":  0,
                }

            # Prefer non-None, non-multicast IPs
            if ip and not is_multicast(ip):
                devices[mac]["ip"] = ip

            # Collect ports this device used
            if p["src_port"]: devices[mac]["ports_seen"].add(p["src_port"])
            if p["dst_port"]: devices[mac]["ports_seen"].add(p["dst_port"])

    # Now refine device types using port context
    for mac, dev in devices.items():
        dev["device_type"] = infer_device_type(dev["vendor"], dev["ports_seen"])

    # ── Traffic counters ─────────────────────────────────────────────────
    # pair_stats[src_label][dst_label] = {count, bytes, protos, ports}
    # dst_label is either a MAC (unicast) or a multicast group IP string
    pair_stats = defaultdict(lambda: defaultdict(lambda: {
        "count": 0, "bytes": 0, "protos": set(), "ports": set()
    }))

    # Multicast group → friendly label
    MCAST_LABELS = {
        "224.0.0.233": "AVB/AVTP Multicast\n224.0.0.233",
        "224.0.0.251": "mDNS Multicast\n224.0.0.251",
        "224.0.0.1":   "All-Hosts Multicast\n224.0.0.1",
        "224.0.0.2":   "All-Routers Multicast\n224.0.0.2",
        "255.255.255.255": "Broadcast\n255.255.255.255",
    }

    for p in packets:
        src_mac = p["src_mac"]
        dst_mac = p["dst_mac"]
        dst_ip  = p["dst_ip"] or ""

        src_is_mcast = int(src_mac.split(':')[0], 16) & 0x01
        dst_is_mcast = int(dst_mac.split(':')[0], 16) & 0x01

        # Sender traffic counter
        if not src_is_mcast and src_mac in devices:
            devices[src_mac]["pkts_sent"]  += 1
            devices[src_mac]["bytes_sent"] += p["orig_len"]

        # Receiver counter — only for unicast destinations
        if not dst_is_mcast and dst_mac in devices:
            devices[dst_mac]["pkts_recv"]  += 1
            devices[dst_mac]["bytes_recv"] += p["orig_len"]

        # Build communication pairs — include multicast destinations
        if src_is_mcast or src_mac not in devices:
            continue

        # Determine destination label
        if dst_is_mcast:
            # Use multicast IP as the destination group label
            dst_label = MCAST_LABELS.get(dst_ip,
                        f"Multicast\n{dst_ip}" if dst_ip else "Multicast\n(unknown)")
        elif dst_mac in devices:
            dst_label = _short_label(devices[dst_mac])
        else:
            continue

        src_label = _short_label(devices[src_mac])
        ps = pair_stats[src_label][dst_label]
        ps["count"] += 1
        ps["bytes"] += p["orig_len"]
        if p["proto"]:
            ps["protos"].add(PROTO_NAMES.get(p["proto"], str(p["proto"])))
        if p["dst_port"]:
            ps["ports"].add(PORT_LABELS.get(p["dst_port"], str(p["dst_port"])))

    # ── Build devices dataframe ──────────────────────────────────────────
    dev_rows = []
    for mac, d in devices.items():
        dev_rows.append({
            "mac":         mac,
            "ip":          d["ip"] or "—",
            "vendor":      d["vendor"],
            "device_type": d["device_type"],
            "pkts_sent":   d["pkts_sent"],
            "pkts_recv":   d["pkts_recv"],
            "pkts_total":  d["pkts_sent"] + d["pkts_recv"],
            "bytes_sent":  d["bytes_sent"],
            "bytes_recv":  d["bytes_recv"],
            "ports":       ", ".join(PORT_LABELS.get(p, str(p))
                                     for p in sorted(d["ports_seen"])
                                     if p in PORT_LABELS) or "—",
        })
    df_dev = pd.DataFrame(dev_rows).sort_values("pkts_total", ascending=False)

    # ── Build pair dataframe ─────────────────────────────────────────────
    pair_rows = []
    for src_label, dsts in pair_stats.items():
        # Recover src device info from label
        src_dev = next((d for d in devices.values()
                        if _short_label(d) == src_label), None)
        for dst_label, ps in dsts.items():
            dst_dev = next((d for d in devices.values()
                            if _short_label(d) == dst_label), None)
            pair_rows.append({
                "src_ip":     src_dev["ip"] if src_dev else "—",
                "src_label":  src_label,
                "dst_ip":     dst_dev["ip"] if dst_dev else dst_label.split('\n')[-1],
                "dst_label":  dst_label,
                "count":      ps["count"],
                "bytes":      ps["bytes"],
                "avg_size":   round(ps["bytes"] / ps["count"], 1) if ps["count"] else 0,
                "protocol":   ", ".join(sorted(ps["protos"])) or "—",
                "services":   ", ".join(sorted(ps["ports"])) or "—",
            })
    df_pair = pd.DataFrame(pair_rows)
    if not df_pair.empty and "count" in df_pair.columns:
        df_pair = df_pair.sort_values("count", ascending=False)

    # ── Generate outputs ─────────────────────────────────────────────────
    print("[*] Generating outputs …")
    _plot_traffic_bar(df_dev, output_dir)
    _write_report(df_dev, df_pair, devices, filepath, condition, output_dir)
    _export_csvs(df_dev, output_dir)

    # ── Console summary ──────────────────────────────────────────────────
    _print_summary(df_dev, df_pair)


def _short_label(dev: dict) -> str:
    """Short display name: vendor + IP."""
    vendor = dev["vendor"].split("/")[0].strip()[:18]
    ip = dev["ip"] or "?"
    return f"{vendor}\n{ip}"


def _device_color(vendor: str) -> str:
    """Consistent color per vendor family for charts."""
    if "Allen" in vendor:   return "#E8704C"
    if "Shure" in vendor:   return "#4C9BE8"
    if "QSC"   in vendor:   return "#4CE87A"
    if "Midas" in vendor or "Behringer" in vendor: return "#E8C44C"
    if "Audinate" in vendor: return "#C44CE8"
    if "Apple" in vendor:   return "#888888"
    if "Realtek" in vendor: return "#AAAAAA"
    return "#CCCCCC"


# ══════════════════════════════════════════════════════════════════════════
#  PLOTTING
# ══════════════════════════════════════════════════════════════════════════

def _plot_heatmap(df_pair: pd.DataFrame, devices: dict, output_dir: str):
    """
    Square heatmap — rows = senders, cols = receivers.
    Cell value = packet count. Only unicast pairs shown.
    """
    if df_pair.empty:
        print("  [!] No unicast pairs — skipping heatmap")
        return

    labels = sorted(set(df_pair["src_label"]) | set(df_pair["dst_label"]))
    n = len(labels)
    if n == 0: return

    idx = {l: i for i, l in enumerate(labels)}
    matrix = np.zeros((n, n), dtype=float)
    for _, row in df_pair.iterrows():
        r, c = idx.get(row["src_label"]), idx.get(row["dst_label"])
        if r is not None and c is not None:
            matrix[r, c] = row["count"]

    tick_labels = [l.replace('\n', '\n') for l in labels]
    fig, ax = plt.subplots(figsize=(max(8, n * 1.1), max(6, n * 0.9)))
    im = ax.imshow(matrix, cmap="YlOrRd", aspect="auto")

    ax.set_xticks(range(n)); ax.set_xticklabels(tick_labels, rotation=45, ha="right", fontsize=7)
    ax.set_yticks(range(n)); ax.set_yticklabels(tick_labels, fontsize=7)
    ax.set_xlabel("Destination Device", fontsize=10)
    ax.set_ylabel("Source Device", fontsize=10)
    ax.set_title("Unicast Packet Count Between Device Pairs\n(row = sender, col = receiver)",
                 fontsize=12, fontweight="bold")

    # Annotate cells with packet counts
    for r in range(n):
        for c in range(n):
            v = matrix[r, c]
            if v > 0:
                ax.text(c, r, f"{int(v)}", ha="center", va="center",
                        fontsize=7, color="black" if v < matrix.max() * 0.6 else "white",
                        fontweight="bold")

    plt.colorbar(im, ax=ax, label="Packet Count")
    plt.tight_layout()
    path = os.path.join(output_dir, "device_comm_heatmap.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [✓] {path}")


def _plot_network_graph(df_pair: pd.DataFrame, df_dev: pd.DataFrame,
                        devices: dict, output_dir: str):
    """
    Force-directed-style network graph.
    Node size ∝ total packets. Edge thickness ∝ packet count.
    Nodes colored by vendor family.
    Uses manual spring layout (no networkx dependency).
    """
    if df_pair.empty:
        return

    # Collect unique node labels and their total traffic
    node_traffic = {}
    for _, row in df_dev.iterrows():
        label = _short_label({"vendor": row["vendor"], "ip": row["ip"] if row["ip"] != "—" else None})
        node_traffic[label] = row["pkts_total"]

    nodes = list(node_traffic.keys())
    n = len(nodes)
    if n == 0: return

    node_idx = {l: i for i, l in enumerate(nodes)}

    # Simple circular layout
    angles = np.linspace(0, 2 * np.pi, n, endpoint=False)
    pos = {l: (np.cos(a) * 3, np.sin(a) * 3) for l, a in zip(nodes, angles)}

    fig, ax = plt.subplots(figsize=(12, 10))
    ax.set_aspect("equal")
    ax.axis("off")
    ax.set_facecolor("#1a1a2e")
    fig.patch.set_facecolor("#1a1a2e")

    max_pkts = max(node_traffic.values()) if node_traffic else 1
    max_edge  = df_pair["count"].max() if not df_pair.empty else 1

    # Draw edges
    for _, row in df_pair.iterrows():
        s, d = row["src_label"], row["dst_label"]
        if s not in pos or d not in pos: continue
        x0, y0 = pos[s]
        x1, y1 = pos[d]
        alpha = 0.2 + 0.6 * (row["count"] / max_edge)
        lw    = 0.5 + 4 * (row["count"] / max_edge)
        ax.plot([x0, x1], [y0, y1], color="#88CCFF", alpha=alpha,
                linewidth=lw, zorder=1, solid_capstyle="round")
        # Arrowhead midpoint
        mx, my = (x0 + x1) / 2, (y0 + y1) / 2
        ax.annotate("", xy=(x1 * 0.85 + x0 * 0.15, y1 * 0.85 + y0 * 0.15),
                    xytext=(mx, my),
                    arrowprops=dict(arrowstyle="->", color="#88CCFF",
                                    lw=max(0.5, lw * 0.5), alpha=alpha),
                    zorder=2)

    # Draw nodes
    for label in nodes:
        x, y = pos[label]
        vendor = label.split('\n')[0]
        color  = _device_color(vendor)
        size   = 200 + 1800 * (node_traffic.get(label, 0) / max_pkts)

        ax.scatter(x, y, s=size, c=color, zorder=3,
                   edgecolors="white", linewidths=1.5, alpha=0.92)
        ax.text(x, y - 0.38, label, ha="center", va="top",
                fontsize=6.5, color="white", zorder=4,
                bbox=dict(boxstyle="round,pad=0.2", fc="#00000088", ec="none"))

    # Legend
    seen_vendors = {}
    for _, row in df_dev.iterrows():
        v = row["vendor"].split("/")[0].strip()
        if v not in seen_vendors:
            seen_vendors[v] = _device_color(row["vendor"])
    patches = [mpatches.Patch(color=c, label=v) for v, c in seen_vendors.items()]
    ax.legend(handles=patches, loc="lower left", fontsize=8,
              facecolor="#2a2a4e", edgecolor="gray", labelcolor="white")

    ax.set_title("Sound Network Device Communication Map\n"
                 "(node size = traffic volume · edge thickness = packet count)",
                 fontsize=12, fontweight="bold", color="white", pad=15)

    path = os.path.join(output_dir, "device_network_graph.png")
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  [✓] {path}")


def _plot_traffic_bar(df_dev: pd.DataFrame, output_dir: str):
    """Horizontal bar chart: packets sent vs received per device."""
    if df_dev.empty: return

    df = df_dev[df_dev["pkts_total"] > 0].head(15).copy()
    df["label"] = df.apply(
        lambda r: f"{r['vendor'].split('/')[0].strip()[:16]}  ({r['ip']})", axis=1
    )

    fig, ax = plt.subplots(figsize=(10, max(4, len(df) * 0.55)))
    y = np.arange(len(df))
    h = 0.38

    colors_sent = [_device_color(v) for v in df["vendor"]]
    colors_recv = [c + "99" for c in colors_sent]  # slightly transparent for recv

    ax.barh(y + h/2, df["pkts_sent"],  h, color=colors_sent,  label="Packets Sent",     alpha=0.9)
    ax.barh(y - h/2, df["pkts_recv"],  h, color=colors_recv,  label="Packets Received",  alpha=0.75)

    ax.set_yticks(y)
    ax.set_yticklabels(df["label"], fontsize=8)
    ax.set_xlabel("Packet Count", fontsize=10)
    ax.set_title("Packets Sent vs Received — Per Device", fontsize=12, fontweight="bold")
    ax.legend(fontsize=9)
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f"{int(x):,}"))
    plt.tight_layout()

    path = os.path.join(output_dir, "device_traffic_bar.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [✓] {path}")


# ══════════════════════════════════════════════════════════════════════════
#  TEXT REPORT
# ══════════════════════════════════════════════════════════════════════════

def _write_report(df_dev, df_pair, devices, filepath, condition, output_dir):
    lines = []
    ts_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines += [
        "=" * 72,
        "  SOUND NETWORK — DEVICE ANALYSIS REPORT",
        f"  Source file : {os.path.basename(filepath)}",
        f"  Condition   : {condition}",
        f"  Generated   : {ts_now}",
        "=" * 72,
        "",
        f"  Total devices identified : {len(df_dev)}",
        f"  Total unicast pairs      : {len(df_pair)}",
        "",
    ]

    # ── Device Inventory ─────────────────────────────────────────────────
    lines += ["─" * 72, "  DEVICE INVENTORY", "─" * 72]
    for i, (_, row) in enumerate(df_dev.iterrows(), 1):
        lines += [
            f"\n  [{i:02d}]  {row['device_type']}",
            f"        IP      : {row['ip']}",
            f"        MAC     : {row['mac']}",
            f"        Vendor  : {row['vendor']}",
            f"        Sent    : {row['pkts_sent']:,} pkts  ({row['bytes_sent']/1000:.1f} KB)",
            f"        Received: {row['pkts_recv']:,} pkts  ({row['bytes_recv']/1000:.1f} KB)",
            f"        Services: {row['ports']}",
        ]

    # ── Top Talkers ──────────────────────────────────────────────────────
    lines += ["", "─" * 72, "  TOP TALKERS (by packets sent)", "─" * 72]
    top_send = df_dev.nlargest(5, "pkts_sent")[["device_type","ip","pkts_sent","bytes_sent"]]
    for _, r in top_send.iterrows():
        lines.append(f"  {r['device_type']:<40}  {r['ip']:<16}  {r['pkts_sent']:>6,} pkts  {r['bytes_sent']/1000:>8.1f} KB")

    lines += ["", "─" * 72, "  TOP RECEIVERS (by packets received)", "─" * 72]
    top_recv = df_dev.nlargest(5, "pkts_recv")[["device_type","ip","pkts_recv","bytes_recv"]]
    for _, r in top_recv.iterrows():
        lines.append(f"  {r['device_type']:<40}  {r['ip']:<16}  {r['pkts_recv']:>6,} pkts  {r['bytes_recv']/1000:>8.1f} KB")


    # ── Device-to-Device Communication ────────────────────────────────────────────
    lines += ["", "─" * 72, "  DEVICE-TO-DEVICE COMMUNICATION", "─" * 72]
    if df_pair.empty:
        lines.append("  No device pairs found.")
    else:
        lines.append(
            f"  {'Source':<33} → {'Destination':<33} {'Pkts':>6}  {'Avg Size':>9}  Protocol / Service"
        )
        lines.append("  " + "-" * 70)
        for _, r in df_pair.iterrows():
            src_vendor = r["src_label"].split("\n")[0][:16]
            dst_vendor = r["dst_label"].split("\n")[0][:16]
            src = f"{r['src_ip']} ({src_vendor})"
            dst = f"{r['dst_ip']} ({dst_vendor})"
            service = r["services"] if r["services"] != "—" else r["protocol"]
            lines.append(
                f"  {src:<33} → {dst:<33} {r['count']:>6,}  {r['avg_size']:>7.0f}B  {service}"
            )
    lines += ["", "=" * 72, "  END OF REPORT", "=" * 72, ""]

    report = "\n".join(lines)
    path = os.path.join(output_dir, "device_analysis_report.txt")
    with open(path, "w") as f:
        f.write(report)
    print(f"  [✓] {path}")


def _export_csvs(df_dev, output_dir):
    p1 = os.path.join(output_dir, "device_inventory.csv")
    df_dev.drop(columns=["bytes_sent","bytes_recv"], errors="ignore").to_csv(p1, index=False)
    print(f"  [✓] {p1}")


def _print_summary(df_dev, df_pair):
    print(f"\n{'='*60}")
    print("  DEVICE SUMMARY")
    print(f"{'='*60}")
    print(f"  {'Device':<38} {'IP':<16} {'Sent':>6}  {'Recv':>6}")
    print("  " + "-" * 56)
    for _, r in df_dev.iterrows():
        dtype = r["device_type"].split("  ", 1)[-1][:36] if "  " in r["device_type"] else r["device_type"][:36]
        print(f"  {dtype:<38} {r['ip']:<16} {r['pkts_sent']:>6,}  {r['pkts_recv']:>6,}")

    if not df_pair.empty:
        print(f"\n  {'─'*60}")
        print("  TOP 5 COMMUNICATING PAIRS")
        print(f"  {'─'*60}")
        for _, r in df_pair.head(5).iterrows():
            print(f"  {r['src_ip']:<16} → {r['dst_ip']:<16}  {r['count']:>4} pkts  {r['services'] or r['protocol']}")
    print(f"{'='*60}\n")


# ══════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="Identify and map devices on the sound network from a pcap/pcapng file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python device_analysis.py  captures/idle.pcapng  --condition idle
  python device_analysis.py  captures/show.pcapng  --condition live --output-dir reports/show1/
        """,
    )
    parser.add_argument("input", help="Path to .pcap or .pcapng file")
    parser.add_argument("--condition", "-c", default="unknown",
                        choices=["idle","live","research","unknown"],
                        help="Measurement condition label (default: unknown)")
    parser.add_argument("--output-dir", "-o", default="reports/device_analysis",
                        help="Output folder for all results (default: reports/device_analysis/)")
    return parser.parse_args()


def main():
    args = parse_args()
    if not os.path.exists(args.input):
        print(f"[!] File not found: {args.input}")
        sys.exit(1)
    analyze(args.input, condition=args.condition, output_dir=args.output_dir)


if __name__ == "__main__":
    main()


## CODE GENERATED WITH CLAUDE
#!/usr/bin/env python3
"""
netscan.py - Pemindai jaringan lokal (LAN)

Menampilkan perangkat yang aktif di jaringan, alamat MAC, nama host,
vendor (perkiraan), dan port TCP yang terbuka pada tiap perangkat.

Hanya memakai library bawaan Python 3.8+ (tanpa pip install).
Jalan di Windows, macOS, dan Linux.

Cara pakai:
    python netscan.py                       -> buka tampilan GUI
    python netscan.py --cli                 -> mode terminal (jaringan terdeteksi otomatis)
    python netscan.py 192.168.1.0/24        -> mode terminal, jaringan tertentu
    python netscan.py -p 22,80,443,8000-8100
    python netscan.py -p 1-1024 --csv hasil.csv

Gunakan HANYA pada jaringan milik Anda atau yang Anda punya izin untuk memindainya.
"""

import argparse
import csv
import errno
import ipaddress
import os
import platform
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace

# --------------------------------------------------------------------------
# Data referensi
# --------------------------------------------------------------------------

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    81: "HTTP-alt", 110: "POP3", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 515: "LPD", 548: "AFP",
    554: "RTSP", 631: "IPP", 873: "rsync", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1723: "PPTP", 1883: "MQTT", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5000: "UPnP/Synology", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 7000: "AirPlay", 8000: "HTTP-alt", 8008: "HTTP-alt",
    8009: "Chromecast", 8080: "HTTP-proxy", 8081: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "HTTP-alt", 9000: "HTTP-alt", 9100: "JetDirect",
    27017: "MongoDB", 62078: "iPhone-sync",
}

# Awalan MAC (OUI) bawaan yang kecil. Untuk cakupan lengkap, gunakan --oui
# dengan file OUI (nmap-mac-prefixes, Wireshark manuf, atau ieee oui.txt).
BUILTIN_OUI = {
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading",
    "005056": "VMware",
    "000C29": "VMware",
    "080027": "VirtualBox",
    "00155D": "Microsoft Hyper-V",
    "525400": "QEMU/KVM",
}

OUI_SEARCH_PATHS = [
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/wireshark/manuf",
    "/usr/share/misc/oui.txt",
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/wireshark/manuf",
    r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes",
    r"C:\Program Files\Nmap\nmap-mac-prefixes",
    r"C:\Program Files\Wireshark\manuf",
]

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # sembunyikan jendela cmd di Windows


# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------

@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    ports: list = field(default_factory=list)
    is_self: bool = False
    scanned: bool = False


# --------------------------------------------------------------------------
# Utilitas jaringan
# --------------------------------------------------------------------------

def local_ip():
    """IP lokal yang dipakai untuk keluar ke jaringan (tidak mengirim paket)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def default_network():
    return str(ipaddress.ip_network(local_ip() + "/24", strict=False))


def own_mac():
    node = uuid.getnode()
    if (node >> 40) & 1:  # bit multicast = MAC acak hasil fallback Python
        return ""
    return ":".join(f"{(node >> s) & 0xFF:02X}" for s in range(40, -8, -8))


def ping(ip, timeout=1.0):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout + 2, creationflags=NO_WINDOW)
    except (subprocess.SubprocessError, OSError):
        return False
    if r.returncode != 0:
        return False
    if system == "windows":  # Windows bisa return 0 untuk "host unreachable"
        return "ttl=" in r.stdout.lower()
    return True


def tcp_alive(ip, timeout=0.4):
    """Cadangan bila perintah ping tidak tersedia: 'refused' pun berarti host hidup."""
    refused = {errno.ECONNREFUSED, 10061}
    for port in (80, 443, 445, 22, 139):
        s = socket.socket()
        s.settimeout(timeout)
        try:
            r = s.connect_ex((ip, port))
        except OSError:
            r = -1
        finally:
            s.close()
        if r == 0 or r in refused:
            return True
    return False


MAC_RE = re.compile(r"((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def norm_mac(raw):
    return ":".join(p.zfill(2) for p in re.split(r"[:-]", raw)).upper()


def _valid_mac(mac):
    return mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") and not mac.startswith("01:00:5E")


def parse_arp(text):
    """Parse keluaran `arp -a` (Windows/macOS/Linux) -> {ip: mac}."""
    entries = {}
    for line in text.splitlines():
        ip, mac = IP_RE.search(line), MAC_RE.search(line)
        if ip and mac:
            m = norm_mac(mac.group(1))
            if _valid_mac(m):
                entries[ip.group(1)] = m
    return entries


def read_arp():
    entries = {}
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=10, creationflags=NO_WINDOW).stdout
        entries = parse_arp(out)
    except (subprocess.SubprocessError, OSError):
        pass
    if not entries and os.path.exists("/proc/net/arp"):  # fallback Linux
        try:
            with open("/proc/net/arp") as f:
                for line in list(f)[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] != "0x0":
                        m = norm_mac(parts[3])
                        if _valid_mac(m):
                            entries[parts[0]] = m
        except OSError:
            pass
    return entries


def resolve_name(ip, timeout=2.0):
    box = {"name": ""}

    def work():
        try:
            box["name"] = socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            pass

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    return box["name"]


# --------------------------------------------------------------------------
# Vendor MAC
# --------------------------------------------------------------------------

def load_oui(extra_path=None):
    oui = dict(BUILTIN_OUI)
    paths = ([extra_path] if extra_path else []) + OUI_SEARCH_PATHS
    for path in paths:
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
                    if m:  # format ieee oui.txt
                        oui[m.group(1).replace("-", "").upper()] = m.group(2).strip()
                        continue
                    m = re.match(r"^([0-9A-Fa-f]{2}[:-]?[0-9A-Fa-f]{2}[:-]?[0-9A-Fa-f]{2})(?:/\d+)?\s+(.+)$", line)
                    if m:  # nmap-mac-prefixes / wireshark manuf
                        key = re.sub(r"[:-]", "", m.group(1)).upper()
                        oui.setdefault(key, m.group(2).split("\t")[-1].strip())
        except OSError:
            continue
        break  # cukup satu file
    return oui


def vendor_of(mac, oui):
    if not mac:
        return ""
    key = mac[:8].replace(":", "")
    if key in oui:
        return oui[key]
    if int(mac[:2], 16) & 0x02:
        return "MAC acak/privat (HP modern)"
    return "Tidak diketahui"


# --------------------------------------------------------------------------
# Port
# --------------------------------------------------------------------------

def service_name(port):
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def fmt_ports(ports):
    return ", ".join(f"{p}/{service_name(p)}" if service_name(p) else str(p) for p in ports)


def parse_ports(spec):
    spec = (spec or "common").strip().lower()
    if spec in ("common", "umum"):
        return sorted(COMMON_PORTS)
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
        else:
            lo = hi = int(part)
        if not (1 <= lo <= hi <= 65535):
            raise ValueError(f"Port tidak valid: {part}")
        ports.update(range(lo, hi + 1))
    if not ports:
        raise ValueError("Daftar port kosong")
    return sorted(ports)


def scan_ports(ip, ports, timeout=0.5, workers=150, stop=None):
    def probe(p):
        if stop is not None and stop.is_set():
            return None
        s = socket.socket()
        s.settimeout(timeout)
        try:
            return p if s.connect_ex((ip, p)) == 0 else None
        except OSError:
            return None
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=workers) as ex:
        return sorted(p for p in ex.map(probe, ports) if p)


# --------------------------------------------------------------------------
# Proses pemindaian utama
# --------------------------------------------------------------------------

def scan(network, ports, port_timeout=0.5, stop=None, on_status=None, on_device=None, oui=None):
    stop = stop or threading.Event()
    status = on_status or (lambda msg, frac=None: None)
    emit = on_device or (lambda d: None)
    oui = oui if oui is not None else load_oui()

    net = ipaddress.ip_network(network, strict=False)
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > 4094:
        raise ValueError("Jaringan terlalu besar (maksimal /20 atau 4094 host).")

    me, my_mac = local_ip(), own_mac()
    check = ping if shutil.which("ping") else tcp_alive

    # Tahap 1: cari perangkat yang menjawab
    status(f"Memeriksa {len(hosts)} alamat...", 0.0)
    alive, done = set(), 0
    with ThreadPoolExecutor(max_workers=128) as ex:
        futs = {ex.submit(check, h): h for h in hosts}
        for f in as_completed(futs):
            done += 1
            if f.result():
                alive.add(futs[f])
            if stop.is_set():
                for x in futs:
                    x.cancel()
                break
            if done % 8 == 0 or done == len(hosts):
                status(f"Memeriksa alamat... {done}/{len(hosts)}", 0.5 * done / len(hosts))
    if stop.is_set():
        return []

    # Tahap 2: gabungkan dengan tabel ARP (menangkap perangkat yang memblokir ping)
    arp = read_arp()
    ips = {ip for ip in arp if ipaddress.ip_address(ip) in net} | alive
    if ipaddress.ip_address(me) in net:
        ips.add(me)

    devices = []
    for ip in sorted(ips, key=lambda x: int(ipaddress.ip_address(x))):
        d = Device(ip=ip, mac=arp.get(ip, ""), is_self=(ip == me))
        if d.is_self and not d.mac:
            d.mac = my_mac
        d.vendor = vendor_of(d.mac, oui)
        devices.append(d)
        emit(replace(d, ports=[]))

    # Tahap 3: hostname + port untuk tiap perangkat
    status(f"Memindai port pada {len(devices)} perangkat...", 0.5)
    finished = 0

    def enrich(d):
        d.hostname = resolve_name(d.ip)
        d.ports = scan_ports(d.ip, ports, timeout=port_timeout, stop=stop)
        d.scanned = True
        return d

    with ThreadPoolExecutor(max_workers=4) as ex:
        for f in as_completed([ex.submit(enrich, d) for d in devices]):
            finished += 1
            d = f.result()
            emit(replace(d, ports=list(d.ports)))
            status(f"Memindai port... {finished}/{len(devices)}", 0.5 + 0.5 * finished / max(1, len(devices)))
    status("Selesai", 1.0)
    return devices


# --------------------------------------------------------------------------
# Ekspor
# --------------------------------------------------------------------------

def export_csv(path, devices):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["IP", "MAC", "Vendor", "Hostname", "Port terbuka"])
        for d in devices:
            w.writerow([d.ip, d.mac, d.vendor, d.hostname, fmt_ports(d.ports)])


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def run_cli(args):
    network = args.network or default_network()
    ports = parse_ports(args.ports)
    print(f"Jaringan : {network}", file=sys.stderr)
    print(f"Port     : {len(ports)} port TCP", file=sys.stderr)

    def status(msg, frac=None):
        sys.stderr.write(f"\r{msg:<60}")
        sys.stderr.flush()

    devices = scan(network, ports, port_timeout=args.timeout, on_status=status, oui=load_oui(args.oui))
    sys.stderr.write("\r" + " " * 60 + "\r")

    rows = [["IP", "MAC", "VENDOR", "HOSTNAME", "PORT TERBUKA"]]
    for d in devices:
        rows.append([d.ip + (" (Anda)" if d.is_self else ""), d.mac or "-", d.vendor or "-",
                     d.hostname or "-", fmt_ports(d.ports) or "-"])
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    for i, r in enumerate(rows):
        print("  ".join(r[j].ljust(widths[j]) for j in range(4)) + "  " + r[4])
        if i == 0:
            print("  ".join("-" * w for w in widths) + "  " + "-" * 12)
    print(f"\n{len(devices)} perangkat aktif ditemukan.")
    if args.csv:
        export_csv(args.csv, devices)
        print(f"Disimpan ke {args.csv}")


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

def run_gui(oui_path=None):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    oui = load_oui(oui_path)
    root = tk.Tk()
    root.title("Network Scanner")
    root.geometry("1000x560")

    q = queue.Queue()
    stop_event = threading.Event()
    devices = {}
    running = {"on": False}

    top = ttk.Frame(root, padding=8)
    top.pack(fill="x")
    ttk.Label(top, text="Jaringan:").grid(row=0, column=0, sticky="w")
    net_var = tk.StringVar(value=default_network())
    ttk.Entry(top, textvariable=net_var, width=20).grid(row=0, column=1, padx=6)
    ttk.Label(top, text="Port:").grid(row=0, column=2, padx=(12, 0))
    port_var = tk.StringVar(value="common")
    ttk.Combobox(top, textvariable=port_var, width=24,
                 values=["common", "1-1024", "22,80,443,8000-8100"]).grid(row=0, column=3, padx=6)
    scan_btn = ttk.Button(top, text="Mulai Scan")
    stop_btn = ttk.Button(top, text="Berhenti", state="disabled")
    export_btn = ttk.Button(top, text="Ekspor CSV", state="disabled")
    scan_btn.grid(row=0, column=4, padx=(12, 4))
    stop_btn.grid(row=0, column=5, padx=4)
    export_btn.grid(row=0, column=6, padx=4)
    ttk.Label(top, text="Port: 'common' = port umum, atau isi mis. 22,80,1000-2000",
              foreground="#666").grid(row=1, column=0, columnspan=7, sticky="w", pady=(4, 0))

    progress = ttk.Progressbar(root, maximum=100)
    progress.pack(fill="x", padx=8)
    status_var = tk.StringVar(value="Siap.")
    ttk.Label(root, textvariable=status_var, padding=(8, 4)).pack(fill="x")

    cols = ("ip", "mac", "vendor", "hostname", "ports")
    heads = {"ip": "IP", "mac": "MAC", "vendor": "Vendor", "hostname": "Hostname", "ports": "Port terbuka"}
    widths = {"ip": 130, "mac": 140, "vendor": 190, "hostname": 190, "ports": 300}
    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
    tree = ttk.Treeview(frame, columns=cols, show="headings")
    for c in cols:
        tree.heading(c, text=heads[c])
        tree.column(c, width=widths[c], anchor="w")
    sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")

    def row_values(d):
        ports = fmt_ports(d.ports) if d.scanned else "memindai..."
        if d.scanned and not d.ports:
            ports = "-"
        return (d.ip + (" (Anda)" if d.is_self else ""), d.mac or "-", d.vendor or "-",
                d.hostname or "-", ports)

    def set_running(on):
        running["on"] = on
        scan_btn.config(state="disabled" if on else "normal")
        stop_btn.config(state="normal" if on else "disabled")
        export_btn.config(state="normal" if (not on and devices) else "disabled")

    def start():
        try:
            ports = parse_ports(port_var.get())
            ipaddress.ip_network(net_var.get(), strict=False)
        except ValueError as e:
            messagebox.showerror("Input tidak valid", str(e))
            return
        tree.delete(*tree.get_children())
        devices.clear()
        stop_event.clear()
        progress["value"] = 0
        set_running(True)
        net = net_var.get()

        def worker():
            try:
                scan(net, ports, stop=stop_event, oui=oui,
                     on_status=lambda m, f=None: q.put(("status", m, f)),
                     on_device=lambda d: q.put(("dev", d, None)))
                q.put(("done", None, None))
            except Exception as e:  # noqa: BLE001
                q.put(("error", str(e), None))

        threading.Thread(target=worker, daemon=True).start()

    def stop():
        stop_event.set()
        status_var.set("Menghentikan...")

    def export():
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                            initialfile="hasil_scan.csv")
        if path:
            export_csv(path, sorted(devices.values(), key=lambda d: int(ipaddress.ip_address(d.ip))))
            status_var.set(f"Disimpan ke {path}")

    def poll():
        try:
            while True:
                kind, a, b = q.get_nowait()
                if kind == "status":
                    status_var.set(a)
                    if b is not None:
                        progress["value"] = b * 100
                elif kind == "dev":
                    devices[a.ip] = a
                    if tree.exists(a.ip):
                        tree.item(a.ip, values=row_values(a))
                    else:
                        tree.insert("", "end", iid=a.ip, values=row_values(a))
                elif kind == "done":
                    set_running(False)
                    n = len(devices)
                    status_var.set("Dihentikan." if stop_event.is_set() else f"Selesai - {n} perangkat aktif.")
                elif kind == "error":
                    set_running(False)
                    messagebox.showerror("Gagal", a)
        except queue.Empty:
            pass
        root.after(100, poll)

    scan_btn.config(command=start)
    stop_btn.config(command=stop)
    export_btn.config(command=export)
    poll()
    root.mainloop()


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Pemindai jaringan lokal: IP, MAC, hostname, port terbuka.")
    ap.add_argument("network", nargs="?", help="mis. 192.168.1.0/24 (default: terdeteksi otomatis)")
    ap.add_argument("-p", "--ports", default="common", help="'common', atau mis. 22,80,1000-2000 (default: common)")
    ap.add_argument("-t", "--timeout", type=float, default=0.5, help="timeout per port, detik (default 0.5)")
    ap.add_argument("--csv", help="simpan hasil ke file CSV")
    ap.add_argument("--oui", help="file OUI untuk lookup vendor MAC yang lebih lengkap")
    ap.add_argument("--cli", action="store_true", help="paksa mode terminal (tanpa GUI)")
    args = ap.parse_args()

    use_cli = args.cli or args.network or args.csv
    if not use_cli:
        try:
            import tkinter  # noqa: F401
        except ImportError:
            print("tkinter tidak tersedia, memakai mode terminal.", file=sys.stderr)
            use_cli = True
    try:
        if use_cli:
            run_cli(args)
        else:
            run_gui(args.oui)
    except ValueError as e:
        sys.exit(f"Error: {e}")
    except KeyboardInterrupt:
        sys.exit("\nDibatalkan.")


if __name__ == "__main__":
    main()

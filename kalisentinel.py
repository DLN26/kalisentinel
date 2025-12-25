
import os
import re
import json
import time
import signal
import argparse
import threading
import subprocess
import ipaddress
import hashlib
from datetime import datetime, timezone
from collections import defaultdict, deque
from typing import Optional, Dict, Any, Deque, List, Tuple, Set

# =========================
# Defaults / Konfiguration
# =========================
DEFAULT_ALERTS_FILE = "/var/log/kalisentinel_alerts.jsonl"
DEFAULT_STATE_DIR = "/var/lib/kalisentinel"

DEFAULT_CONFIG_FILE = "/etc/kalisentinel/config.json"
DEFAULT_IOC_FILE = "/etc/kalisentinel/iocs.json"
DEFAULT_SYSTEMD_UNIT = "/etc/systemd/system/kalisentinel.service"

DEFAULT_PERSISTENCE_STATE = os.path.join(DEFAULT_STATE_DIR, "persistence_state.json")
DEFAULT_DNS_STATE = os.path.join(DEFAULT_STATE_DIR, "dns_state.json")
DEFAULT_TAMPER_STATE = os.path.join(DEFAULT_STATE_DIR, "tamper_state.json")
DEFAULT_IOC_STATE = os.path.join(DEFAULT_STATE_DIR, "ioc_state.json")

SUMMARY_INTERVAL = 120  # Sekunden

CANDIDATE_LOGS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/messages",
]

SUSPICIOUS_PATTERNS = [
    ("SSH_FAILED", re.compile(r"Failed password for (invalid user )?.* from (\S+)")),
    ("SSH_ACCEPT", re.compile(r"Accepted (password|publickey) for (\S+) from (\S+)")),
    ("SUDO", re.compile(r"sudo: .*")),
    ("CRON", re.compile(r"CRON\[\d+\]: \(.*\) CMD \((.*)\)")),
]

_stop = threading.Event()

# =========================
# Summary Stats (Modul 5)
# =========================
summary_lock = threading.Lock()
summary_stats = {
    "events_total": 0,
    "by_category": defaultdict(int),
    "by_severity": defaultdict(int),
    "modules": defaultdict(int),  # MOD1/MOD2/MOD3/MOD4/BASE
    "ssh_fails": 0,
    "unique_ips": set(),
}
last_summary_ts = time.time()

# =========================
# Runtime Config
# =========================
config_lock = threading.Lock()
runtime_config: Dict[str, Any] = {
    "whitelist_ips": {"127.0.0.1", "::1"},
    "webhook_url": "",

    # Modul 1
    "persistence_interval": 20,  # Sekunden

    # Modul 2
    "dns_interval": 5,           # Sekunden (Polling fürs Journal)
    "dns_burst_window": 60,      # Sekunden
    "dns_burst_max": 120,        # Queries pro Window (Burst Alarm)

    # Modul 3 (IOC)
    "ioc_interval": 60,          # Sekunden
    "ioc_max_file_mb": 30,       # max file size to hash
    "ioc_paths": [               # files/dirs to check (optional)
        "/usr/local/bin",
        "/usr/local/sbin",
        "/tmp",
        "/var/tmp",
    ],

    # Modul 4 (Tamper)
    "tamper_interval": 15,       # Sekunden
}

# =========================
# Helper
# =========================
def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def _write_json(path: str, obj: Any) -> None:
    _safe_mkdir(os.path.dirname(path))
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception:
        pass

def _read_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _inc_summary(severity: str, category: str, module: str, ip: Optional[str] = None) -> None:
    with summary_lock:
        summary_stats["events_total"] += 1
        summary_stats["by_category"][category] += 1
        summary_stats["by_severity"][severity] += 1
        summary_stats["modules"][module] += 1
        if ip:
            summary_stats["unique_ips"].add(ip)

def emit(alerts_file, severity, category, message, data=None, webhook_url="", module="BASE", ip: Optional[str]=None):
    alert = {
        "ts": now_iso(),
        "severity": severity,
        "category": category,
        "message": message,
        "data": data or {},
        "team": "blue",
        "tool": "KaliSentinel",
        "module": module,
    }

    print(f"[{alert['ts']}] [{severity}] [{category}] {message}")

    _safe_mkdir(os.path.dirname(alerts_file))
    with open(alerts_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")

    _inc_summary(severity, category, module, ip=ip)

    if webhook_url:
        try:
            subprocess.run(
                ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json",
                 "-d", json.dumps(alert, ensure_ascii=False), webhook_url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

def load_config(path: str) -> Dict[str, Any]:
    cfg = _read_json(path, {})
    if isinstance(cfg, dict):
        return cfg
    return {}

def apply_config(cfg: Dict[str, Any]) -> None:
    with config_lock:
        for k, v in cfg.items():
            runtime_config[k] = v

# =========================
# Modul 1: File & Persistence Detection
# =========================
PERSISTENCE_PATHS = [
    "/etc/systemd/system",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/etc/init.d",
    "/etc/rc.local",
    "/etc/ssh",
    "/root/.ssh",
    "/home/kali/.ssh",
    "/usr/local/bin",
    "/usr/local/sbin",
]

PERSISTENCE_EXCLUDE_PREFIXES = [
    "/etc/systemd/system/multi-user.target.wants/",
    "/etc/systemd/system/sysinit.target.wants/",
    "/etc/systemd/system/timers.target.wants/",
]

def _is_excluded(path: str) -> bool:
    return any(path.startswith(pfx) for pfx in PERSISTENCE_EXCLUDE_PREFIXES)

def _stat_entry(path: str) -> Optional[Dict[str, Any]]:
    try:
        st = os.stat(path, follow_symlinks=False)
        return {"mtime": float(st.st_mtime), "size": int(st.st_size)}
    except (FileNotFoundError, PermissionError):
        return None
    except Exception:
        return None

def _walk_paths(paths: List[str]) -> Dict[str, Dict[str, Any]]:
    snap: Dict[str, Dict[str, Any]] = {}
    for base in paths:
        if not os.path.exists(base):
            continue
        if os.path.isfile(base):
            if not _is_excluded(base):
                ent = _stat_entry(base)
                if ent:
                    snap[base] = ent
            continue

        for root, _dirs, files in os.walk(base):
            for fn in files:
                full = os.path.join(root, fn)
                if _is_excluded(full):
                    continue
                ent = _stat_entry(full)
                if ent:
                    snap[full] = ent
    return snap

def _load_snapshot(state_file: str) -> Dict[str, Dict[str, Any]]:
    data = _read_json(state_file, {})
    snap = data.get("snapshot") if isinstance(data, dict) else None
    return snap if isinstance(snap, dict) else {}

def _save_snapshot(state_file: str, snapshot: Dict[str, Dict[str, Any]]) -> None:
    _write_json(state_file, {"snapshot": snapshot, "ts": now_iso()})

def persistence_monitor(alerts_file: str, state_file: str):
    with config_lock:
        webhook_url = runtime_config.get("webhook_url", "")
        interval = int(runtime_config.get("persistence_interval", 20))

    prev = _load_snapshot(state_file)
    if not prev:
        base = _walk_paths(PERSISTENCE_PATHS)
        _save_snapshot(state_file, base)
        emit(
            alerts_file, "LOW", "PERSISTENCE",
            "Baseline erstellt (erster Start). Ab jetzt werden Änderungen gemeldet.",
            {"paths": PERSISTENCE_PATHS, "items": len(base), "state_file": state_file},
            webhook_url, module="MOD1"
        )
        prev = base

    while not _stop.is_set():
        with config_lock:
            webhook_url = runtime_config.get("webhook_url", "")
            interval = int(runtime_config.get("persistence_interval", 20))

        cur = _walk_paths(PERSISTENCE_PATHS)

        prev_keys = set(prev.keys())
        cur_keys = set(cur.keys())

        new_files = sorted(cur_keys - prev_keys)
        removed_files = sorted(prev_keys - cur_keys)

        changed_files: List[Tuple[str, Dict[str, Any], Dict[str, Any]]] = []
        for p in (prev_keys & cur_keys):
            if prev[p].get("mtime") != cur[p].get("mtime") or prev[p].get("size") != cur[p].get("size"):
                changed_files.append((p, prev[p], cur[p]))

        for p in new_files[:50]:
            emit(alerts_file, "WARN", "PERSISTENCE_NEWFILE",
                 f"Neue Datei in Persistence-Pfad: {p}",
                 {"path": p, "stat": cur.get(p)}, webhook_url, module="MOD1")

        for p in removed_files[:50]:
            emit(alerts_file, "WARN", "PERSISTENCE_REMOVED",
                 f"Datei entfernt aus Persistence-Pfad: {p}",
                 {"path": p}, webhook_url, module="MOD1")

        for p, old, new in changed_files[:50]:
            emit(alerts_file, "WARN", "PERSISTENCE_CHANGED",
                 f"Datei verändert in Persistence-Pfad: {p}",
                 {"path": p, "before": old, "after": new}, webhook_url, module="MOD1")

        _save_snapshot(state_file, cur)
        prev = cur
        time.sleep(max(5, interval))

# =========================
# Modul 2: DNS-Detection
# =========================
DNS_SUSPICIOUS_TLDS = {"ru", "cn", "kp", "ir", "su", "top", "xyz", "click", "work", "zip", "mov"}
DNS_ALLOWLIST_SUFFIXES: Set[str] = set()
_dns_domain_rx = re.compile(r"\b([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")

def _looks_like_dga(domain: str) -> bool:
    d = domain.lower().strip(".")
    labels = d.split(".")
    if not labels:
        return False
    label = labels[0]
    if len(label) < 12:
        return False
    vowels = set("aeiou")
    v = sum(1 for c in label if c in vowels)
    digits = sum(1 for c in label if c.isdigit())
    cons = sum(1 for c in label if c.isalpha() and c not in vowels)
    return (v <= 2) and ((cons + digits) >= 10)

def _tld(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    return parts[-1] if len(parts) >= 2 else ""

def _allowlisted(domain: str) -> bool:
    d = domain.lower().strip(".")
    return any(d == sfx or d.endswith("." + sfx) for sfx in DNS_ALLOWLIST_SUFFIXES)

def _journal_available() -> bool:
    return subprocess.run(["bash", "-lc", "command -v journalctl >/dev/null 2>&1"]).returncode == 0

def _read_dns_journal_since(cursor_state: Dict[str, Any]) -> List[str]:
    since = cursor_state.get("since", int(time.time()) - 5)
    units = ["systemd-resolved", "dnsmasq"]
    lines: List[str] = []
    for unit in units:
        cmd = ["journalctl", "-u", unit, "--since", f"@{since}", "-o", "cat", "--no-pager"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True)
            if p.stdout:
                lines.extend(p.stdout.splitlines())
        except Exception:
            continue
    cursor_state["since"] = int(time.time())
    return lines

def dns_monitor(alerts_file: str):
    if not _journal_available():
        emit(alerts_file, "LOW", "DNS", "journalctl nicht verfügbar – DNS-Detection übersprungen.", module="MOD2")
        return

    cursor_state: Dict[str, Any] = _read_json(DEFAULT_DNS_STATE, {"since": int(time.time()) - 5})
    dq: Deque[float] = deque()

    while not _stop.is_set():
        with config_lock:
            webhook_url = runtime_config.get("webhook_url", "")
            interval = int(runtime_config.get("dns_interval", 5))
            burst_window = int(runtime_config.get("dns_burst_window", 60))
            burst_max = int(runtime_config.get("dns_burst_max", 120))

        lines = _read_dns_journal_since(cursor_state)
        _write_json(DEFAULT_DNS_STATE, cursor_state)

        for line in lines:
            m = _dns_domain_rx.search(line)
            if not m:
                continue
            domain = m.group(0).lower().strip(".")
            if _allowlisted(domain):
                continue

            now = time.time()
            dq.append(now)
            while dq and (now - dq[0]) > burst_window:
                dq.popleft()
            if len(dq) == burst_max:
                emit(alerts_file, "WARN", "DNS_BURST",
                     f"Viele DNS-Anfragen: {len(dq)} in {burst_window}s",
                     {"count": len(dq), "window": burst_window},
                     webhook_url, module="MOD2")

            reasons = []
            tld = _tld(domain)
            if tld in DNS_SUSPICIOUS_TLDS:
                reasons.append(f"suspicious_tld:{tld}")
            if _looks_like_dga(domain):
                reasons.append("dga_like")

            if reasons:
                emit(alerts_file, "WARN", "DNS",
                     f"Verdächtige DNS-Anfrage: {domain}",
                     {"domain": domain, "reasons": reasons, "raw": line[:300]},
                     webhook_url, module="MOD2")

        time.sleep(max(1, interval))

# =========================
# BASE: Network Detection
# =========================
NETWORK_INTERVAL = 30
SUSPICIOUS_PORTS = {4444, 1337, 6666, 9001, 31337}

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def parse_network():
    result = subprocess.run(["ss", "-tunp"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "users:(" not in line:
            continue
        m = re.search(r'(\S+)\s+.*\s+(\S+):\d+\s+(\S+):(\d+).*users:\(\("([^"]+)"', line)
        if not m:
            continue
        yield m.group(5), m.group(3), int(m.group(4)), m.group(1)

def network_monitor(alerts_file: str):
    seen = set()
    while not _stop.is_set():
        with config_lock:
            webhook_url = runtime_config.get("webhook_url", "")
        for proc, ip, port, proto in parse_network():
            key = (proc, ip, port)
            if key in seen:
                continue
            seen.add(key)

            reasons = []
            if not is_private_ip(ip):
                reasons.append("external_ip")
            if port in SUSPICIOUS_PORTS:
                reasons.append("suspicious_port")

            if reasons:
                emit(
                    alerts_file, "WARN", "NETWORK",
                    f"Ungewöhnliche Verbindung: {proc} → {ip}:{port}",
                    {"process": proc, "dst_ip": ip, "dst_port": port, "reasons": reasons, "proto": proto},
                    webhook_url, module="BASE"
                )
        time.sleep(NETWORK_INTERVAL)

# =========================
# BASE: Log Monitoring
# =========================
def tail_follow(path: str):
    f = open(path, "r", errors="replace")
    f.seek(0, os.SEEK_END)
    while not _stop.is_set():
        line = f.readline()
        if line:
            yield line.rstrip()
        else:
            time.sleep(0.2)

def monitor_file(path: str, alerts_file: str):
    with config_lock:
        webhook_url = runtime_config.get("webhook_url", "")
    emit(alerts_file, "LOW", "INFO", f"Monitoring gestartet: {path}", webhook_url=webhook_url, module="BASE")

    for line in tail_follow(path):
        with config_lock:
            webhook_url = runtime_config.get("webhook_url", "")
        for name, rx in SUSPICIOUS_PATTERNS:
            m = rx.search(line)
            if not m:
                continue

            if name == "SSH_FAILED":
                ip = m.group(2)
                with summary_lock:
                    summary_stats["ssh_fails"] += 1
                    summary_stats["unique_ips"].add(ip)
                emit(alerts_file, "WARN", "SSH", f"SSH Fail von {ip}", {"ip": ip, "raw": line[:300]},
                     webhook_url, module="BASE", ip=ip)

            elif name == "SSH_ACCEPT":
                emit(alerts_file, "LOW", "SSH", "SSH Login OK", {"raw": line[:300]}, webhook_url, module="BASE")

            elif name == "SUDO":
                emit(alerts_file, "LOW", "PRIVESC", "Sudo Aktivität", {"raw": line[:300]}, webhook_url, module="BASE")

            elif name == "CRON":
                emit(alerts_file, "LOW", "CRON", "Cron Job", {"raw": line[:300]}, webhook_url, module="BASE")

# =========================
# Modul 3: Malware IOC-Checks
# =========================
def _sha256_file(path: str, max_mb: int) -> Optional[str]:
    try:
        st = os.stat(path, follow_symlinks=False)
        if st.st_size > (max_mb * 1024 * 1024):
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def _load_iocs(ioc_file: str) -> Dict[str, Any]:
    """
    Format /etc/kalisentinel/iocs.json (Beispiel):
    {
      "sha256": ["...hash..."],
      "paths": ["/path/to/suspicious.bin"],
      "process_names": ["badproc", "xmrig"],
      "remote_ips": ["1.2.3.4"],
      "domains": ["evil.example"]
    }
    """
    data = _read_json(ioc_file, {})
    if not isinstance(data, dict):
        return {}
    for k in ["sha256", "paths", "process_names", "remote_ips", "domains"]:
        if k in data and not isinstance(data[k], list):
            data[k] = []
    return data

def _list_process_names() -> Set[str]:
    names = set()
    try:
        p = subprocess.run(["ps", "-eo", "comm="], capture_output=True, text=True)
        for line in p.stdout.splitlines():
            n = line.strip()
            if n:
                names.add(n)
    except Exception:
        pass
    return names

def _list_remote_ips_from_ss() -> Set[str]:
    ips = set()
    try:
        p = subprocess.run(["ss", "-tun"], capture_output=True, text=True)
        for line in p.stdout.splitlines():
            # rough parse: last column often peer addr:port
            parts = line.split()
            if len(parts) < 5:
                continue
            peer = parts[4]
            # peer might be "1.2.3.4:443" or "[2001:db8::1]:443"
            peer = peer.strip()
            peer = peer.strip("[]")
            if ":" in peer:
                # ipv4:port OR ipv6:port (hard) -> best effort:
                if peer.count(":") == 1:
                    ip = peer.split(":")[0]
                else:
                    ip = peer.rsplit(":", 1)[0]
            else:
                ip = peer
            # validate
            try:
                ipaddress.ip_address(ip)
                ips.add(ip)
            except Exception:
                continue
    except Exception:
        pass
    return ips

def _iter_files_from_paths(paths: List[str]) -> List[str]:
    out: List[str] = []
    for base in paths:
        if not os.path.exists(base):
            continue
        if os.path.isfile(base):
            out.append(base)
            continue
        for root, _dirs, files in os.walk(base):
            for fn in files:
                out.append(os.path.join(root, fn))
    return out

def ioc_monitor(alerts_file: str, ioc_file: str, state_file: str):
    last_hits = _read_json(state_file, {"seen": []})
    seen_hits = set(last_hits.get("seen", [])) if isinstance(last_hits, dict) else set()

    while not _stop.is_set():
        with config_lock:
            webhook_url = runtime_config.get("webhook_url", "")
            interval = int(runtime_config.get("ioc_interval", 60))
            max_mb = int(runtime_config.get("ioc_max_file_mb", 30))
            scan_paths = list(runtime_config.get("ioc_paths", []))

        iocs = _load_iocs(ioc_file)
        sha_iocs = set(x.lower() for x in iocs.get("sha256", []))
        path_iocs = set(iocs.get("paths", []))
        proc_iocs = set(iocs.get("process_names", []))
        ip_iocs = set(iocs.get("remote_ips", []))
        domain_iocs = set(iocs.get("domains", []))  # currently used mainly by DNS module; kept for completeness

        # 1) process name match
        procs = _list_process_names()
        for bad in proc_iocs:
            if bad in procs:
                key = f"proc:{bad}"
                if key not in seen_hits:
                    seen_hits.add(key)
                    emit(alerts_file, "HIGH", "IOC_PROCESS",
                         f"IOC Treffer: Prozess läuft ({bad})",
                         {"process": bad}, webhook_url, module="MOD3")

        # 2) remote IP match
        remote_ips = _list_remote_ips_from_ss()
        for bad_ip in ip_iocs:
            if bad_ip in remote_ips:
                key = f"rip:{bad_ip}"
                if key not in seen_hits:
                    seen_hits.add(key)
                    emit(alerts_file, "HIGH", "IOC_REMOTE_IP",
                         f"IOC Treffer: Verbindung zu Remote-IP ({bad_ip})",
                         {"remote_ip": bad_ip}, webhook_url, module="MOD3", ip=bad_ip)

        # 3) explicit suspicious path existence + hash match
        for pth in path_iocs:
            if os.path.exists(pth):
                h = _sha256_file(pth, max_mb)
                key = f"path:{pth}:{h or 'nohash'}"
                if key not in seen_hits:
                    seen_hits.add(key)
                    emit(alerts_file, "HIGH", "IOC_PATH",
                         f"IOC Treffer: Datei vorhanden ({pth})",
                         {"path": pth, "sha256": h}, webhook_url, module="MOD3")

        # 4) hash scan over configured directories (lightweight, best-effort)
        if sha_iocs and scan_paths:
            for fp in _iter_files_from_paths(scan_paths):
                h = _sha256_file(fp, max_mb)
                if not h:
                    continue
                if h.lower() in sha_iocs:
                    key = f"sha:{h}:{fp}"
                    if key not in seen_hits:
                        seen_hits.add(key)
                        emit(alerts_file, "HIGH", "IOC_SHA256",
                             "IOC Treffer: SHA256 Match",
                             {"path": fp, "sha256": h}, webhook_url, module="MOD3")

        _write_json(state_file, {"seen": sorted(seen_hits), "ts": now_iso(), "ioc_file": ioc_file, "domains": list(domain_iocs)})
        time.sleep(max(10, interval))

# =========================
# Modul 4: Tamper-Protection
# =========================
def _fingerprint(path: str) -> Optional[Dict[str, Any]]:
    try:
        st = os.stat(path, follow_symlinks=False)
        fp = {"path": path, "mtime": float(st.st_mtime), "size": int(st.st_size)}
        # optional hash for smaller files
        h = _sha256_file(path, max_mb=10)
        if h:
            fp["sha256"] = h
        return fp
    except Exception:
        return None

def tamper_monitor(alerts_file: str, state_file: str, script_path: str, config_path: str, unit_path: str):
    with config_lock:
        webhook_url = runtime_config.get("webhook_url", "")
        interval = int(runtime_config.get("tamper_interval", 15))

    targets = [script_path, config_path, unit_path]
    prev = _read_json(state_file, {}).get("targets", {})
    if not isinstance(prev, dict) or not prev:
        base = {}
        for t in targets:
            fp = _fingerprint(t)
            if fp:
                base[t] = fp
        _write_json(state_file, {"targets": base, "ts": now_iso()})
        emit(alerts_file, "LOW", "TAMPER",
             "Tamper-Baseline erstellt (Script/Config/Service-Unit).",
             {"targets": list(base.keys()), "state_file": state_file},
             webhook_url, module="MOD4")
        prev = base

    while not _stop.is_set():
        with config_lock:
            webhook_url = runtime_config.get("webhook_url", "")
            interval = int(runtime_config.get("tamper_interval", 15))

        cur = {}
        for t in targets:
            fp = _fingerprint(t)
            if fp:
                cur[t] = fp

        # compare
        for t, old in prev.items():
            new = cur.get(t)
            if not new:
                emit(alerts_file, "HIGH", "TAMPER_MISSING",
                     f"Tamper: Datei fehlt/kein Zugriff: {t}",
                     {"path": t, "before": old},
                     webhook_url, module="MOD4")
                continue
            if old.get("mtime") != new.get("mtime") or old.get("size") != new.get("size") or old.get("sha256") != new.get("sha256"):
                emit(alerts_file, "HIGH", "TAMPER_CHANGED",
                     f"Tamper: Datei verändert: {t}",
                     {"path": t, "before": old, "after": new},
                     webhook_url, module="MOD4")

        # also detect new targets (rare)
        for t in cur.keys() - prev.keys():
            emit(alerts_file, "WARN", "TAMPER_NEW_TARGET",
                 f"Tamper: neuer Target-Fingerprint: {t}",
                 {"path": t, "after": cur[t]},
                 webhook_url, module="MOD4")

        prev = cur
        _write_json(state_file, {"targets": cur, "ts": now_iso()})
        time.sleep(max(5, interval))

# =========================
# Modul 5: Zentrale Zusammenfassung
# =========================
def summary_loop(alerts_file: str):
    global last_summary_ts
    while not _stop.is_set():
        now = time.time()
        if now - last_summary_ts >= SUMMARY_INTERVAL:
            with config_lock:
                webhook_url = runtime_config.get("webhook_url", "")

            with summary_lock:
                total = summary_stats["events_total"]
                by_cat = dict(summary_stats["by_category"])
                by_sev = dict(summary_stats["by_severity"])
                by_mod = dict(summary_stats["modules"])
                ssh_fails = summary_stats["ssh_fails"]
                unique_ips = list(summary_stats["unique_ips"])

                # reset window
                summary_stats["events_total"] = 0
                summary_stats["by_category"].clear()
                summary_stats["by_severity"].clear()
                summary_stats["modules"].clear()
                summary_stats["ssh_fails"] = 0
                summary_stats["unique_ips"].clear()

            if total > 0:
                emit(
                    alerts_file, "WARN", "SUMMARY",
                    f"Zusammenfassung ({SUMMARY_INTERVAL//60} Min): Events={total}, SSH-Fails={ssh_fails}, IPs={len(unique_ips)}",
                    {
                        "events_total": total,
                        "ssh_fails": ssh_fails,
                        "unique_ips": unique_ips[:200],
                        "by_severity": by_sev,
                        "by_category": by_cat,
                        "by_module": by_mod,
                    },
                    webhook_url, module="MOD5"
                )

            last_summary_ts = now

        time.sleep(1)

# =========================
# Main
# =========================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default=DEFAULT_ALERTS_FILE)
    ap.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    ap.add_argument("--config", default=DEFAULT_CONFIG_FILE)
    ap.add_argument("--ioc-file", default=DEFAULT_IOC_FILE)
    ap.add_argument("--unit-file", default=DEFAULT_SYSTEMD_UNIT)
    args = ap.parse_args()

    signal.signal(signal.SIGINT, lambda *_: _stop.set())
    signal.signal(signal.SIGTERM, lambda *_: _stop.set())

    # load config overlay
    cfg = load_config(args.config)
    apply_config(cfg)

    logs = [p for p in CANDIDATE_LOGS if os.path.exists(p)]
    if not logs:
        print("Keine Logs gefunden.")
        return

    _safe_mkdir(args.state_dir)

    # BASE: Log Monitoring (2 Logs)
    for log in logs[:2]:
        threading.Thread(target=monitor_file, args=(log, args.output), daemon=True).start()

    # BASE: Network Monitoring
    threading.Thread(target=network_monitor, args=(args.output,), daemon=True).start()

    # MOD1: Persistence Monitoring
    persistence_state = os.path.join(args.state_dir, "persistence_state.json")
    threading.Thread(target=persistence_monitor, args=(args.output, persistence_state), daemon=True).start()

    # MOD2: DNS Monitoring
    threading.Thread(target=dns_monitor, args=(args.output,), daemon=True).start()

    # MOD3: IOC Monitoring
    ioc_state = os.path.join(args.state_dir, "ioc_state.json")
    threading.Thread(target=ioc_monitor, args=(args.output, args.ioc_file, ioc_state), daemon=True).start()

    # MOD4: Tamper Monitoring
    tamper_state = os.path.join(args.state_dir, "tamper_state.json")
    script_path = os.path.abspath(__file__)
    threading.Thread(
        target=tamper_monitor,
        args=(args.output, tamper_state, script_path, args.config, args.unit_file),
        daemon=True
    ).start()

    # MOD5: Central Summary
    threading.Thread(target=summary_loop, args=(args.output,), daemon=True).start()

    print("KaliSentinel läuft (Blue Team) – BASE + MOD1..MOD5")
    while not _stop.is_set():
        time.sleep(1)

if __name__ == "__main__":
    main()

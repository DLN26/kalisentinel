# KaliSentinel (Blue Team Mini-EDR) 

KaliSentinel ist ein leichtgewichtiges Blue-Team Monitoring-Tool für Linux/Kali:

Tested on Kali Linux 2025.x (systemd-based)

- **BASE**: Log-Monitoring (SSH/Sudo/Cron) + Network-Detection via `ss`
- **MOD1**: Persistence Detection (systemd/cron/ssh/rc.local …)
- **MOD2**: DNS Detection (journalctl: systemd-resolved/dnsmasq, Burst + DGA/TLD Heuristiken)
- **MOD3**: IOC Checks (Prozesse, Remote-IPs, Pfade, SHA256 Hashes)
- **MOD4**: Tamper Protection (Fingerprint von Script/Config/Unit)
- **MOD5**: Periodische Zusammenfassung (Summary Events)

Output: **JSONL Alerts** nach `/var/log/kalisentinel_alerts.jsonl`.

---

## Features 
- JSONL Alerts + Console Output
- Konfiguration über `/etc/kalisentinel/config.json`
- IOC-Datei über `/etc/kalisentinel/iocs.json`
- systemd Service (Autostart)
- State Files in `/var/lib/kalisentinel/`

---

## Anforderungen
- Linux (getestet auf Kali)
- Python 3
- systemd
- `ss` (iproute2)
- `journalctl` (systemd)

---

## Installation (Manuell)
### 1) 
```bash
sudo mkdir -p /opt/kalisentinel /etc/kalisentinel /var/lib/kalisentinel

sudo cp kalisentinel.py /opt/kalisentinel/kalisentinel.py
sudo cp packaging/config.json /etc/kalisentinel/config.json
sudo cp packaging/iocs.json /etc/kalisentinel/iocs.json
sudo cp packaging/kalisentinel.service /etc/systemd/system/kalisentinel.service

sudo chmod 755 /opt/kalisentinel/kalisentinel.py
sudo chmod 644 /etc/kalisentinel/config.json
sudo chmod 644 /etc/kalisentinel/iocs.json
sudo chmod 644 /etc/systemd/system/kalisentinel.service

sudo systemctl daemon-reload
sudo systemctl enable --now kalisentinel

# 🔐 Kali Linux Security Event Monitor (kali-sem)

![GitHub](https://img.shields.io/badge/License-MIT-blue.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/Dynamo2k1/Log_Monitor)
![GitHub repo size](https://img.shields.io/github/repo-size/Dynamo2k1/Log_Monitor)

> **Advanced real-time security monitoring for Kali Linux**  
> Specialized for offensive security professionals and red team operations

## 🚀 Features

- 🕵️ **Real-time auth.log monitoring** with inotify
- 🔥 **Multi-protocol detection** (SSH, Sudo, Console, GUI, Metasploit)
- 🌍 **IP geolocation** integration (via ipinfo.io)
- 📊 **Risk classification** (Critical/High/Medium/Low)
- 🔄 **Automatic log rotation** handling
- 📁 **Secure backups** with encryption
- 💻 **Kali-optimized** for pentesting workflows

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Dynamo2k1/Log_Monitor.git
cd Log_Monitor

# Make executable
chmod +x kali-sem.sh

# Install dependencies
sudo apt update && sudo apt install inotify-tools jq
```

## 🛠️ Usage

```bash
# Start monitoring (as root)
sudo ./log_monitor.sh start

# Stop monitoring
sudo ./log_monitor.sh stop
```

## ⚙️ Configuration

Edit these variables in the script:

```bash
# Alert sensitivity
ALERT_THRESHOLD=3         # Failed attempts before alert

# Backup settings
BACKUP_ROOT="/var/log/security_archive"

# API Configuration (optional)
API_TOKEN="your_ipinfo_token"  # For geolocation
```

## 📝 Log Patterns Detected

| Protocol | Detection Patterns | Risk Level |
|----------|--------------------|------------|
| SSH      | `Failed password`, `authentication failure` | 🔴 High |
| Sudo     | `incorrect password attempts` | 🚨 Critical |
| Console  | `FAILED SU`, `LOGIN FAILURE` | 🟠 Medium |
| GUI      | `gdm`, `gnome` sessions | 🟡 Low |
| Metasploit | `msfconsole` events | 🟢 Info |

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Open a Pull Request

## 📜 License

MIT © [Dynamo](https://github.com/Dynamo2k1)

---

> **Pro Tip**: For best results, run alongside `fail2ban` for automated blocking of brute force attacks!  
> ⚠️ **Warning**: This tool requires root privileges to access auth.log

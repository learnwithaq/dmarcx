# DMARCX

A command-line tool built in Python to check the **DMARC**, **SPF**, and **DKIM** DNS records of any domain. This tool helps security analysts, penetration testers, and sysadmins verify email authentication mechanisms to improve domain security and prevent spoofing or phishing.

## 🚀 Features

- ✅ DMARC record detection with policy color highlighting:
  - 🔴 `p=none`
  - 🟡 `p=quarantine`
  - 🔵 `p=reject`
- ✅ SPF record validation
- ✅ DKIM selector-based lookup (default: `default`)
- 🧠 Simple CLI interface
- 🎨 Colored terminal output using `termcolor`
- 🔓 Open-source (GPLv3)

---

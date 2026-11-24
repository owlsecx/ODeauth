# 🦉 ODeauth

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Wireless%20/%20RF-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **ODeauth** — 802.11 Deauth/Disassoc Analyzer ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

ODeauth is an offline-first OwlSec tool for 802.11 Deauth/Disassoc Analyzer. It provides an interactive cyan terminal UI and a full CLI with multi-format export (TXT, Markdown, JSON, CSV, SARIF), designed for authorized security work on Linux.

---

## ✨ Features

- Offline analysis of 802.11 deauthentication and disassociation frames from pcap
- Reason-code decoding, retry/protected-frame awareness and sequence analysis
- Burst, micro-burst and wave-gap detection for injection tells
- Radiotap signal/frequency correlation and top-victim ranking
- Validation mode with exit codes for automation
- Export findings as TXT, Markdown, JSON, CSV or SARIF

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o ODeauth ODeauth.go
./ODeauth --help
./ODeauth --input capture.pcap
./ODeauth --input capture.pcap --validate
./ODeauth --reason 7 --format json
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

**GNU General Public License v3.0** — © 2026 Owlsec LLC

This tool is free software: its full source code is published in this repository and you may study, modify and redistribute it under the GPL-3.0.

> Other OwlSec tools are separate, independent programs under their own terms; many remain proprietary.

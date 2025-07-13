# IP Camera Security Assessment Framework

## Overview

This framework automates scanning, vulnerability checking, and credential testing for IP cameras from popular vendors like Hikvision, Dahua, Reolink, Axis, Foscam, and AVTech.

## Features

- Extended port scanning for common IP camera ports
- Banner grabbing and vendor identification (including HTTPS support)
- Modular PoC vulnerability checks
- Automated default credential testing (HTTP and HTTPS)
- Concurrent scanning for speed
- CSV output for easy reporting
- Firmware analysis helper script included

## Requirements

- Python 3.8+
- `requests`
- `python-nmap` (requires `nmap` installed on your system)
- `concurrent.futures` (built-in)

Install dependencies:

```bash
pip install -r requirements.txt

# 🔍 Network Port Scanner

A fast, multithreaded network port scanner with service detection
and banner grabbing, built in Python.

## Features
- Multithreaded scanning (up to 500 threads)
- Service identification for 17 common services
- Banner grabbing
- Hostname resolution
- Configurable timeout and port ranges

## Installation
```bash
git clone https://github.com/YOUR_USERNAME/network-port-scanner.git
cd network-port-scanner
pip install -r requirements.txt
```

## Usage
```bash
# Scan common ports on a target
python src/scanner.py -t 192.168.1.1 -p 1-1024

# Full scan with more threads
python src/scanner.py -t 192.168.1.1 -p 1-65535 --threads 200

# Slow scan with longer timeout
python src/scanner.py -t 192.168.1.1 -p 1-1024 --timeout 3
```

## ⚠️ Legal Notice
Only scan systems you own or have explicit permission to test.

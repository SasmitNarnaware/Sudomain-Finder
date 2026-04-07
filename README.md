# Nmap Subdomain Scanner

## Overview

Nmap Subdomain Scanner is a Python-based reconnaissance tool designed to assist in basic bug bounty and security research workflows. It automates the process of discovering subdomains, identifying live hosts, and performing service and port scans.

This tool is intended for learning and controlled security testing.

---

## Features

* Subdomain enumeration using subfinder
* Live host detection using httpx
* Automated port and service scanning using nmap
* Multi-step reconnaissance pipeline
* Output saved in structured text files

---

## Workflow

The tool follows a sequential reconnaissance process:

```
Target Domain
    ↓
Subdomain Enumeration (subfinder)
    ↓
Live Host Filtering (httpx)
    ↓
Port and Service Scanning (nmap)
    ↓
Results Stored in Output Files
```

---

## Requirements

Ensure the following dependencies are installed and properly configured:

### Python

* Python 3.10 or higher

### Go

Required for installing subfinder and httpx
https://go.dev/dl/

### Tools

Install using:

```
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Nmap

Download from:
https://nmap.org/download.html

Ensure all tools are added to your system PATH.

---

## Installation

```
git clone https://github.com/SasmitNarnaware/Sudomain-Finder.git
cd Nmap_Subdomain_Finder
```

---

## Usage

Run the script:

```
python main.py
```

Enter the target domain when prompted:

```
example.com
```

---

## Output

### subdomains.txt

Contains all discovered subdomains.

### alive.txt

Contains only responsive (live) subdomains.

### scan_results.txt

Contains nmap scan results for live targets.

---

## Performance Considerations

* Only live domains are scanned to reduce unnecessary processing
* Multithreading can be implemented to improve speed
* Scan intensity depends on nmap configuration

---

## Disclaimer

This tool is intended for educational purposes only.
Do not use it against systems without proper authorization.
The author is not responsible for misuse or damage caused by this tool.

---

## Future Improvements

* Structured output formats (JSON, CSV)
* Integration with vulnerability scanning tools
* Enhanced filtering and prioritization
* CLI argument support

---

## Contributions and Suggestions

For suggestions, improvements, or collaboration inquiries, contact:

Email: [sasmit.cybersec@gmail.com](mailto:sasmit.cybersec@gmail.com)

---

## Author

Developed as part of a learning initiative in cybersecurity and bug bounty reconnaissance.

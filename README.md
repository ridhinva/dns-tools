# DNSTools - DNS Security Toolkit

Comprehensive DNS security analysis toolkit for investigating DNS configurations, detecting misconfigurations, and identifying DNS-based attack vectors.

## Features

- DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV)
- Zone transfer attempt detection
- DNS cache poisoning detection hints
- DNSSEC validation
- DNS over HTTPS (DoH) queries
- Reverse DNS lookups
- DNS history lookup
- SPF/DKIM/DMARC email security checks
- Subdomain takeover detection
- DNS wildcard detection
- Bulk domain analysis

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/dns-tools.git
cd dns-tools
pip3 install -r requirements.txt
chmod +x dnstools.py
```

## Usage

### DNS Record Lookup
```bash
python3 dnstools.py records example.com
python3 dnstools.py records example.com --types A,MX,NS,TXT
```

### Zone Transfer Test
```bash
python3 dnstools.py zonetransfer example.com
```

### DNSSEC Validation
```bash
python3 dnstools.py dnssec example.com
```

### Email Security Check (SPF/DKIM/DMARC)
```bash
python3 dnstools.py email-security example.com
```

### Reverse DNS
```bash
python3 dnstools.py rdns 8.8.8.8
python3 dnstools.py rdns 8.8.8.0/24
```

### Subdomain Takeover Check
```bash
python3 dnstools.py takeover example.com -w subdomains.txt
```

### DNS Cache Poisoning Check
```bash
python3 dnstools.py cache-poison example.com
```

### Full DNS Audit
```bash
python3 dnstools.py full example.com --output json --output-file audit.json
```

## Security Checks

| Check | Severity | Description |
|-------|----------|-------------|
| Zone Transfer | CRITICAL | AXFR allowed to any host |
| Missing SPF | HIGH | Email spoofing risk |
| Missing DMARC | HIGH | No email authentication policy |
| Missing DKIM | MEDIUM | No email signing |
| DNSSEC Missing | MEDIUM | No DNS integrity verification |
| DNS Wildcard | LOW | Wildcard DNS records present |
| Open Resolver | HIGH | DNS amplification attack risk |

## Legal Disclaimer

Only use on domains you own or have authorization to test. DNS enumeration without authorization may be illegal.

## License

MIT License

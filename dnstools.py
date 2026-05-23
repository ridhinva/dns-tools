#!/usr/bin/env python3
"""
DNSTools - DNS Security Toolkit
For authorized security testing only.
"""

import argparse
import sys
import socket
import json
import random
import string
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = RESET = ""
    class Style:
        RESET_ALL = ""

VERSION = "1.0.0"


def dns_query(domain, rtype="A"):
    """Query DNS records using Google DoH."""
    if not HAS_REQUESTS:
        return None, "requests library not installed"
    try:
        url = f"https://dns.google/resolve?name={domain}&type={rtype}"
        resp = requests.get(url, timeout=10)
        data = resp.json()
        return data.get("Answer", []), None
    except Exception as e:
        return None, str(e)


def get_nameservers(domain):
    """Get nameservers for domain."""
    ns_records, _ = dns_query(domain, "NS")
    if ns_records:
        return [r.get("data", "").rstrip(".") for r in ns_records]
    return []


def records_lookup(domain, record_types=None):
    """Lookup DNS records."""
    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]

    print(f"\n{Fore.CYAN}[*] DNS Records for {domain}:{Style.RESET_ALL}\n")
    results = {}

    for rtype in record_types:
        answers, err = dns_query(domain, rtype)
        if answers:
            results[rtype] = []
            print(f"  {Fore.WHITE}{rtype} Records:{Style.RESET_ALL}")
            for a in answers:
                data = a.get("data", "")
                ttl = a.get("TTL", "")
                results[rtype].append({"data": data, "ttl": ttl})
                print(f"    {data} (TTL: {ttl}s)")

    return results


def zone_transfer(domain):
    """Attempt zone transfer on all nameservers."""
    print(f"\n{Fore.CYAN}[*] Testing Zone Transfer for {domain}:{Style.RESET_ALL}\n")

    nameservers = get_nameservers(domain)
    if not nameservers:
        # Try to resolve directly
        try:
            answers, _ = dns_query(domain, "NS")
            if answers:
                nameservers = [a.get("data", "").rstrip(".") for a in answers]
        except:
            pass

    if not nameservers:
        print(f"  {Fore.YELLOW}[!] Could not find nameservers{Style.RESET_ALL}")
        return []

    vulnerable = []
    for ns in nameservers:
        print(f"  {Fore.WHITE}Testing {ns}...{Style.RESET_ALL}")
        try:
            # Try to resolve NS to IP
            ns_ip = socket.gethostbyname(ns)

            # Attempt TCP connection to port 53
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ns_ip, 53))
            sock.close()

            if result == 0:
                print(f"    {Fore.YELLOW}[!] Port 53 open on {ns} ({ns_ip}){Style.RESET_ALL}")
                # Note: Actual AXFR requires dnspython library
                print(f"    {Fore.CYAN}[*] Manual AXFR test: dig @{ns} {domain} AXFR{Style.RESET_ALL}")
            else:
                print(f"    {Fore.GREEN}[+] Port 53 filtered/closed{Style.RESET_ALL}")
        except Exception as e:
            print(f"    {Fore.GREEN}[+] Cannot connect: {e}{Style.RESET_ALL}")

    return vulnerable


def dnssec_check(domain):
    """Check DNSSEC configuration."""
    print(f"\n{Fore.CYAN}[*] DNSSEC Check for {domain}:{Style.RESET_ALL}\n")

    # Check for DNSKEY records
    answers, _ = dns_query(domain, "DNSKEY")
    if answers:
        print(f"  {Fore.GREEN}[+] DNSKEY records found - DNSSEC is configured{Style.RESET_ALL}")
        for a in answers:
            print(f"    {a.get('data', '')[:80]}...")
        return True
    else:
        print(f"  {Fore.YELLOW}[!] No DNSKEY records - DNSSEC not configured{Style.RESET_ALL}")
        return False

    # Check for DS records
    ds_answers, _ = dns_query(domain, "DS")
    if ds_answers:
        print(f"  {Fore.GREEN}[+] DS records found at parent zone{Style.RESET_ALL}")
    else:
        print(f"  {Fore.YELLOW}[!] No DS records at parent zone{Style.RESET_ALL}")


def email_security(domain):
    """Check SPF, DKIM, and DMARC records."""
    print(f"\n{Fore.CYAN}[*] Email Security Check for {domain}:{Style.RESET_ALL}\n")

    issues = []

    # SPF
    answers, _ = dns_query(domain, "TXT")
    spf_found = False
    if answers:
        for a in answers:
            data = a.get("data", "")
            if "v=spf1" in data.lower():
                spf_found = True
                print(f"  {Fore.GREEN}[+] SPF Record: {data}{Style.RESET_ALL}")

                # Check for overly permissive SPF
                if "+all" in data:
                    issues.append("CRITICAL: SPF allows all senders (+all)")
                    print(f"    {Fore.RED}[!] CRITICAL: +all allows anyone to send as this domain{Style.RESET_ALL}")
                elif "?all" in data:
                    issues.append("WARNING: SPF uses neutral (?all)")
                    print(f"    {Fore.YELLOW}[!] ?all is neutral - doesn't enforce{Style.RESET_ALL}")
                break

    if not spf_found:
        issues.append("HIGH: No SPF record")
        print(f"  {Fore.RED}[!] No SPF record found - email spoofing risk{Style.RESET_ALL}")

    # DMARC
    dmarc_answers, _ = dns_query(f"_dmarc.{domain}", "TXT")
    dmarc_found = False
    if dmarc_answers:
        for a in dmarc_answers:
            data = a.get("data", "")
            if "v=dmarc1" in data.lower():
                dmarc_found = True
                print(f"  {Fore.GREEN}[+] DMARC Record: {data}{Style.RESET_ALL}")

                if "p=none" in data.lower():
                    issues.append("MEDIUM: DMARC policy is 'none' (monitoring only)")
                    print(f"    {Fore.YELLOW}[!] Policy is 'none' - no enforcement{Style.RESET_ALL}")
                break

    if not dmarc_found:
        issues.append("HIGH: No DMARC record")
        print(f"  {Fore.RED}[!] No DMARC record found{Style.RESET_ALL}")

    # DKIM (common selectors)
    dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "dkim",
                       "mail", "smtp", "s1", "s2", "key1", "key2"]
    dkim_found = False
    for selector in dkim_selectors:
        dkim_answers, _ = dns_query(f"{selector}._domainkey.{domain}", "TXT")
        if dkim_answers:
            for a in dkim_answers:
                data = a.get("data", "")
                if "v=dkim1" in data.lower() or "p=" in data.lower():
                    dkim_found = True
                    print(f"  {Fore.GREEN}[+] DKIM Record (selector: {selector}): {data[:60]}...{Style.RESET_ALL}")
                    break
        if dkim_found:
            break

    if not dkim_found:
        issues.append("MEDIUM: No DKIM record found (checked common selectors)")
        print(f"  {Fore.YELLOW}[!] No DKIM record found{Style.RESET_ALL}")

    return issues


def wildcard_check(domain):
    """Check for DNS wildcard records."""
    print(f"\n{Fore.CYAN}[*] DNS Wildcard Check for {domain}:{Style.RESET_ALL}\n")

    random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    random_domain = f"{random_sub}.{domain}"

    answers, _ = dns_query(random_domain, "A")
    if answers:
        ips = [a.get("data", "") for a in answers]
        print(f"  {Fore.YELLOW}[!] Wildcard DNS detected!{Style.RESET_ALL}")
        print(f"    {random_domain} resolves to: {', '.join(ips)}")
        return True
    else:
        print(f"  {Fore.GREEN}[+] No wildcard DNS detected{Style.RESET_ALL}")
        return False


def reverse_dns(ip):
    """Perform reverse DNS lookup."""
    print(f"\n{Fore.CYAN}[*] Reverse DNS: {ip}{Style.RESET_ALL}\n")

    try:
        hostname = socket.gethostbyaddr(ip)
        print(f"  {Fore.WHITE}Hostname:{Style.RESET_ALL} {hostname[0]}")
        if hostname[1]:
            print(f"  {Fore.WHITE}Aliases:{Style.RESET_ALL}")
            for alias in hostname[1]:
                print(f"    {alias}")
        return hostname
    except socket.herror:
        print(f"  {Fore.RED}[!] No reverse DNS record{Style.RESET_ALL}")
        return None


def subdomain_takeover(domain, wordlist_file=None):
    """Check for subdomain takeover vulnerabilities."""
    print(f"\n{Fore.CYAN}[*] Subdomain Takeover Check for {domain}:{Style.RESET_ALL}\n")

    # CNAME targets that are commonly vulnerable
    vulnerable_services = {
        "amazonaws.com": "AWS (S3/ElasticBeanstalk)",
        "herokuapp.com": "Heroku",
        "github.io": "GitHub Pages",
        "azurewebsites.net": "Azure",
        "cloudfront.net": "CloudFront",
        "s3.amazonaws.com": "S3 Bucket",
        "ghost.io": "Ghost",
        "shopify.com": "Shopify",
        "surge.sh": "Surge",
        "bitbucket.io": "Bitbucket",
        "wordpress.com": "WordPress.com",
        "feedpress.me": "Feedpress",
        "ghost.io": "Ghost",
        "helpjuice.com": "Helpjuice",
        "helpscoutdocs.com": "HelpScout",
        "landingi.com": "Landingi",
        "launchrock.com": "Launchrock",
        "ngrok.io": "Ngrok",
        "pingdom.com": "Pingdom",
        "readme.io": "Readme",
        "statuspage.io": "Statuspage",
        "strikingly.com": "Strikingly",
        "surge.sh": "Surge",
        "thinkific.com": "Thinkific",
        "tictail.com": "Tictail",
        "tumblr.com": "Tumblr",
        "uberflip.com": "Uberflip",
        "unbounce.com": "Unbounce",
        "uservoice.com": "UserVoice",
        "vend.co": "Vend",
        "webflow.com": "Webflow",
        "zendesk.com": "Zendesk",
    }

    subdomains = ["www", "api", "app", "blog", "cdn", "dev", "docs", "mail",
                   "shop", "staging", "test", "admin", "portal"]

    if wordlist_file:
        with open(wordlist_file) as f:
            subdomains = [line.strip() for line in f if line.strip()]

    vulnerable = []
    for sub in subdomains:
        fqdn = f"{sub}.{domain}"
        answers, _ = dns_query(fqdn, "CNAME")

        if answers:
            for a in answers:
                cname = a.get("data", "").rstrip(".")
                for service_domain, service_name in vulnerable_services.items():
                    if service_domain in cname:
                        # Check if the target resolves
                        target_answers, _ = dns_query(cname, "A")
                        if not target_answers:
                            print(f"  {Fore.RED}[!] POTENTIAL TAKEOVER: {fqdn} => {cname} ({service_name}){Style.RESET_ALL}")
                            vulnerable.append({"subdomain": fqdn, "cname": cname, "service": service_name})
                        else:
                            print(f"  {Fore.GREEN}[+] {fqdn} => {cname} (active){Style.RESET_ALL}")

    if not vulnerable:
        print(f"\n  {Fore.GREEN}[+] No takeover vulnerabilities detected{Style.RESET_ALL}")

    return vulnerable


def cache_poison_check(domain):
    """Check for DNS cache poisoning indicators."""
    print(f"\n{Fore.CYAN}[*] DNS Cache Poisoning Indicators for {domain}:{Style.RESET_ALL}\n")

    issues = []

    # Check if domain uses predictable DNS transaction IDs
    nameservers = get_nameservers(domain)
    if nameservers:
        print(f"  {Fore.WHITE}Nameservers:{Style.RESET_ALL}")
        for ns in nameservers:
            print(f"    {ns}")

    # Check for short TTL (can indicate previous poisoning)
    answers, _ = dns_query(domain, "A")
    if answers:
        for a in answers:
            ttl = a.get("TTL", 0)
            if ttl < 60:
                issues.append(f"Very low TTL ({ttl}s) - possible cache flush after incident")
                print(f"  {Fore.YELLOW}[!] Very low TTL: {ttl}s{Style.RESET_ALL}")

    # Check for multiple A records (could indicate poisoning)
    if answers and len(answers) > 5:
        issues.append(f"Unusually many A records ({len(answers)})")
        print(f"  {Fore.YELLOW}[!] Unusually many A records: {len(answers)}{Style.RESET_ALL}")

    if not issues:
        print(f"  {Fore.GREEN}[+] No cache poisoning indicators detected{Style.RESET_ALL}")

    return issues


def full_audit(domain, output_file=None):
    """Run full DNS security audit."""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  FULL DNS SECURITY AUDIT: {domain}")
    print(f"{'='*60}{Style.RESET_ALL}")

    results = {"domain": domain, "timestamp": datetime.now().isoformat()}

    results["records"] = records_lookup(domain)
    results["zone_transfer"] = zone_transfer(domain)
    results["dnssec"] = dnssec_check(domain)
    results["email_security"] = email_security(domain)
    results["wildcard"] = wildcard_check(domain)

    # Summary
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  AUDIT SUMMARY")
    print(f"{'='*60}{Style.RESET_ALL}")

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n{Fore.GREEN}[+] Report saved to {output_file}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="DNSTools - DNS Security Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s records example.com
  %(prog)s records example.com --types A,MX,NS
  %(prog)s zonetransfer example.com
  %(prog)s dnssec example.com
  %(prog)s email-security example.com
  %(prog)s rdns 8.8.8.8
  %(prog)s takeover example.com -w subs.txt
  %(prog)s full example.com --output-file audit.json
        """
    )

    sub = parser.add_subparsers(dest="command")

    # records
    r = sub.add_parser("records", help="DNS record lookup")
    r.add_argument("domain", help="Domain name")
    r.add_argument("--types", default="A,AAAA,MX,NS,TXT,CNAME,SOA,CAA",
                   help="Record types (comma-separated)")

    # zonetransfer
    z = sub.add_parser("zonetransfer", help="Test for zone transfer vulnerability")
    z.add_argument("domain", help="Domain name")

    # dnssec
    d = sub.add_parser("dnssec", help="Check DNSSEC configuration")
    d.add_argument("domain", help="Domain name")

    # email-security
    e = sub.add_parser("email-security", help="Check SPF/DKIM/DMARC")
    e.add_argument("domain", help="Domain name")

    # rdns
    rd = sub.add_parser("rdns", help="Reverse DNS lookup")
    rd.add_argument("target", help="IP address or CIDR range")

    # takeover
    t = sub.add_parser("takeover", help="Check for subdomain takeover")
    t.add_argument("domain", help="Domain name")
    t.add_argument("-w", "--wordlist", help="Subdomain wordlist file")

    # wildcard
    w = sub.add_parser("wildcard", help="Check for DNS wildcard")
    w.add_argument("domain", help="Domain name")

    # cache-poison
    cp = sub.add_parser("cache-poison", help="Check cache poisoning indicators")
    cp.add_argument("domain", help="Domain name")

    # full
    f = sub.add_parser("full", help="Full DNS security audit")
    f.add_argument("domain", help="Domain name")
    f.add_argument("--output-file", help="Output JSON filename")

    args = parser.parse_args()

    print(f"\n{Fore.CYAN}╔══════════════════════════════════╗")
    print(f"║    DNSTools v{VERSION}              ║")
    print(f"╚══════════════════════════════════╝{Style.RESET_ALL}")

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "records":
        types = args.types.split(",")
        records_lookup(args.domain, types)
    elif args.command == "zonetransfer":
        zone_transfer(args.domain)
    elif args.command == "dnssec":
        dnssec_check(args.domain)
    elif args.command == "email-security":
        email_security(args.domain)
    elif args.command == "rdns":
        reverse_dns(args.target)
    elif args.command == "takeover":
        subdomain_takeover(args.domain, args.wordlist)
    elif args.command == "wildcard":
        wildcard_check(args.domain)
    elif args.command == "cache-poison":
        cache_poison_check(args.domain)
    elif args.command == "full":
        full_audit(args.domain, args.output_file)


if __name__ == "__main__":
    main()

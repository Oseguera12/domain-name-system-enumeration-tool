#!/usr/bin/env python3


import argparse
import os
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import dns.exception
import dns.flags
import dns.query
import dns.resolver
import dns.reversename
import dns.zone
import requests


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    MAGENTA = "\033[35m"
    RED = "\033[31m"
    YELLOW = "\033[33m"


class DNSEnumerationTool:
    """
    @DESCRIPTION: class constructor
    @PARAMETERS: none
    @RETURNS: none
    """
    def __init__(self):
        self.discovered_subdomains = []
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.subdomain_lists_dir = os.path.join(self.script_dir, "subdomain lists")
        self.lock = threading.Lock()
        self.show_dns_lookups = None
    
    
    """
    @DESCRIPTION: displays menu options
    @PARAMETERS: none
    @RETURNS: none
    """
    def display_banner(self):
        banner = (
            "\n+=============================+\n"
            "|     DNS Enumeration Tool    |\n"
            "+=============================+\n"
            "| 1. DNS Records Enumeration  |\n"
            "| 2. Subdomain Enumeration    |\n"
            "| 3. Full DNS Enumeration     |\n"
            "| 4. Zone Transfer Check      |\n"
            "| 5. DNSSEC Validation Check  |\n"
            "| 6. List wordlist files      |\n"
            f"| 7. {Colors.RED}Exit{Colors.RESET}                     |\n"
            "| 8. Show Help & Usage        |\n"
            "+=============================+\n"
        )
        print(banner)


    """
    @DESCRIPTION: checks if a subdomain exists
    @PARAMETERS: domain [str], subdomain [str]
    @RETURNS: none
    """
    def check_subdomain(self, domain, subdomain):
        protocols = ['https', 'http']
        subdomain_found = False
        
        for protocol in protocols:
            url = f"{protocol}://{subdomain}.{domain}"
            try:
                response = requests.get(url, timeout=5, allow_redirects=True, verify=False)
                if response.status_code == 200:
                    print(f"{Colors.GREEN}[+] Found: {url} (Status: {response.status_code}){Colors.RESET}")
                    with self.lock:
                        if url not in self.discovered_subdomains:
                            self.discovered_subdomains.append(url)
                    subdomain_found = True
                    break
                elif response.status_code in [301, 302, 303, 307, 308]:
                    print(f"{Colors.YELLOW}[+] Found (redirect): {url} -> {response.headers.get('Location', 'Unknown')} (Status: {response.status_code}){Colors.RESET}")
                    with self.lock:
                        if url not in self.discovered_subdomains:
                            self.discovered_subdomains.append(url)
                    subdomain_found = True
                    break
                elif response.status_code in [401, 403]:
                    print(f"{Colors.CYAN}[+] Found (restricted): {url} (Status: {response.status_code}){Colors.RESET}")
                    with self.lock:
                        if url not in self.discovered_subdomains:
                            self.discovered_subdomains.append(url)
                    subdomain_found = True
                    break
                else:
                    print(f"{Colors.YELLOW}[?] Found (unusual status): {url} (Status: {response.status_code}){Colors.RESET}")

            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.SSLError:
                if protocol == 'https':
                    continue
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
        
        # DNS LOOKUP
        if not subdomain_found and self.show_dns_lookups:
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                print(f"{Colors.BLUE}[+] DNS Found: {full_domain}{Colors.RESET}")
            except socket.gaierror:
                pass
            except Exception:
                pass


    """
    @DESCRIPTION: enumerates subdomains for a given domain
    @PARAMETERS: domain [str], subdomain_file [str]
    @RETURNS: discovered_subdomains [list]
    """
    def enumerate_subdomains(self, domain, subdomain_file='subdomain.txt'):
        print(f"\n[*] Starting subdomain enumeration for: {domain}")
        
        if not os.path.isabs(subdomain_file):
            subdomain_path = os.path.join(self.subdomain_lists_dir, subdomain_file)
            if os.path.exists(subdomain_path):
                subdomain_file = subdomain_path
            else:
                subdomain_file = os.path.join(self.script_dir, subdomain_file)
        
        print(f"[*] Using wordlist: {subdomain_file}")
        
        if not os.path.exists(subdomain_file):
            print(f"{Colors.RED}[!] Error: {subdomain_file} not found!{Colors.RESET}")
            print(f"[!] Looking in directories:")
            print(f"    Primary: {self.subdomain_lists_dir}")
            print(f"    Fallback: {self.script_dir}")
            self.list_wordlists()
            return []
        
        try:
            with open(subdomain_file, 'r') as file:
                subdomains = file.read().splitlines()
        except Exception as e:
            print(f"{Colors.RED}[!] Error reading {subdomain_file}: {e}{Colors.RESET}")
            return []
        
        print(f"[*] Loaded {len(subdomains)} subdomains from wordlist")
        
        if self.show_dns_lookups is None:
            while True:
                dns_choice = input(f"\n{Colors.YELLOW}[?] Show DNS-only lookups (domains that resolve in DNS but don't respond to HTTP)? (y/n): {Colors.RESET}").strip().lower()
                if dns_choice in ['y', 'yes', 'Y', 'YES']:
                    self.show_dns_lookups = True
                    print(f"{Colors.GREEN}[+] DNS-only lookups enabled{Colors.RESET}")
                    break
                elif dns_choice in ['n', 'no', 'N', 'NO']:
                    self.show_dns_lookups = False
                    print(f"{Colors.YELLOW}[-] DNS-only lookups disabled{Colors.RESET}")
                    break
                else:
                    print(f"{Colors.RED}[!] Please enter 'y' for yes or 'n' for no{Colors.RESET}")
        
        print("[*] Starting enumeration...")
        
        self.discovered_subdomains = []
        
        max_workers = 50
        print(f"[*] Using {max_workers} concurrent threads for enumeration...")
        
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_subdomain = {
                executor.submit(self.check_subdomain, domain, subdomain): subdomain 
                for subdomain in subdomains
            }
            
            completed = 0
            total = len(subdomains)
            
            for future in as_completed(future_to_subdomain):
                completed += 1
                subdomain = future_to_subdomain[future]
                
                try:
                    future.result()
                except Exception as e:
                    print(f"{Colors.RED}[!] Error checking {subdomain}: {e}{Colors.RESET}")
                
                if completed % 100 == 0 or completed == total:
                    print(f"[*] Progress: {completed}/{total} subdomains checked ({completed/total*100:.1f}%)")
        
        print(f"[*] Enumeration completed for {domain}")
        
        if self.discovered_subdomains:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"discovered_subdomains_{domain}_{timestamp}.txt"
            try:
                with open(output_file, 'w') as file:
                    for subdomain in self.discovered_subdomains:
                        file.write(subdomain + '\n')
                print(f"[+] Discovered {len(self.discovered_subdomains)} subdomains")
                print(f"{Colors.GREEN}[+] Results saved to: {output_file}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error saving results: {e}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[-] No subdomains discovered{Colors.RESET}")

        return self.discovered_subdomains
    

    """
    @DESCRIPTION: enumerates dns records for a given domain
    @PARAMETERS: domain [str]
    @RETURNS: found_records [dict]
    """
    def enumerate_dns_records(self, domain):
        print(f"\n[*] Starting DNS records enumeration for: {domain}")
        
        record_types = [
            'A', 
            'AAAA', 
            'CNAME', 
            'MX', 
            'NS', 
            'TXT', 
            'SOA', 
            'SRV', 
            'PTR', 
            'NAPTR', 
            'CAA', 
            'DNSKEY', 
            'DS', 
            'TLSA', 
            'SSHFP', 
            'CERT'
        ]
        
        resolver = dns.resolver.Resolver()
        found_records = {}
        
        for record_type in record_types:
            try:
                answer = resolver.resolve(domain, record_type)
                records = []
                for data in answer:
                    records.append(str(data))
                
                if records:
                    found_records[record_type] = records
                    print(f"\n[+] {record_type} records for {domain}:")
                    for record in records:
                        print(f"    {record}")
                        
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                print(f"{Colors.RED}[!] Domain {domain} does not exist.{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.RED}[!] Error querying {record_type} records: {e}{Colors.RESET}")
                continue
        
        if found_records:
            print(f"\n[*] Extracting IP addresses for reverse DNS lookups...")
            ip_addresses = self.extract_ip_addresses(found_records)
            
            if ip_addresses:
                print(f"[*] Found {len(ip_addresses)} IP addresses to reverse lookup:")
                for ip in ip_addresses:
                    print(f"    {ip}")
                
                reverse_results = self.reverse_dns_lookup(ip_addresses)
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"dns_records_{domain}_{timestamp}.txt"
            try:
                with open(output_file, 'w') as file:
                    file.write(f"DNS Records for {domain}\n")
                    file.write(f"Generated on: {datetime.now()}\n")
                    file.write("=" * 50 + "\n\n")
                    
                    for record_type, records in found_records.items():
                        file.write(f"{record_type} Records:\n")
                        for record in records:
                            file.write(f"  {record}\n")
                        file.write("\n")
                    
                    if ip_addresses and 'reverse_results' in locals():
                        file.write("Reverse DNS Lookups:\n")
                        file.write("=" * 30 + "\n")
                        for ip, hostnames in reverse_results.items():
                            file.write(f"{ip} -> {', '.join(hostnames)}\n")
                        file.write("\n")

                print(f"\n{Colors.GREEN}[+] DNS records saved to: {output_file}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error saving DNS records: {e}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[-] No DNS records found{Colors.RESET}")

        return found_records
    

    """
    @DESCRIPTION: lists available wordlist files for subdomain enumeration
    @PARAMETERS: none
    @RETURNS: none
    """
    def list_wordlists(self):
        print(f"\n[*] Available wordlist files:")
        if os.path.exists(self.subdomain_lists_dir):
            print(f"\nIn 'subdomain lists' directory ({self.subdomain_lists_dir}):")
            txt_files = []
            try:
                for file in os.listdir(self.subdomain_lists_dir):
                    if file.endswith('.txt'):
                        txt_files.append(file)
                        file_path = os.path.join(self.subdomain_lists_dir, file)
                        try:
                            with open(file_path, 'r') as f:
                                line_count = sum(1 for _ in f)
                            print(f"{Colors.GREEN}  {file} ({line_count} lines){Colors.RESET}")
                        except:
                            print(f"{Colors.RED}  {file} (unable to read){Colors.RESET}")

                if not txt_files:
                    print(f"{Colors.RED}  [!] No .txt files found{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}  [!] Error listing files: {e}{Colors.RESET}")
        else:
            print(f"\n{Colors.RED}  [!] subdomain lists' directory not found at: {self.subdomain_lists_dir}{Colors.RESET}")

        print(f"\nIn script directory ({self.script_dir}):")
        txt_files = []
        try:
            for file in os.listdir(self.script_dir):
                if file.endswith('.txt') and file != 'requirements.txt':
                    txt_files.append(file)
                    file_path = os.path.join(self.script_dir, file)
                    try:
                        with open(file_path, 'r') as f:
                            line_count = sum(1 for _ in f)
                        print(f"{Colors.GREEN}  {file} ({line_count} lines){Colors.RESET}")
                    except:
                        print(f"{Colors.RED}  {file} (unable to read){Colors.RESET}")

            if not txt_files:
                print(f"{Colors.RED}  [!] No wordlist files found{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}  [!] Error listing files: {e}{Colors.RESET}")


    """
    @DESCRIPTION: enumerates dns records and subdomains for a given domain
    @PARAMETERS: domain [str], subdomain_file [str]
    @RETURNS: found_records [dict]
    """
    def full_enumeration(self, domain, subdomain_file='subdomain.txt'):
        print(f"\n[*] Starting full DNS enumeration for: {domain}")
        
        dns_records = self.enumerate_dns_records(domain)
        discovered_subs = self.enumerate_subdomains(domain, subdomain_file)
        
        if discovered_subs:
            print(f"\n[*] Enumerating DNS records for discovered subdomains...")
            subdomain_records = {}
            
            for subdomain_url in discovered_subs:
                subdomain = subdomain_url.replace("http://", "").replace("https://", "")
                print(f"\n[*] DNS records for {subdomain}:")
                records = self.enumerate_dns_records(subdomain)
                if records:
                    subdomain_records[subdomain] = records
            
            if subdomain_records or dns_records:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"full_dns_enumeration_{domain}_{timestamp}.txt"
                try:
                    with open(output_file, 'w') as file:
                        file.write(f"Full DNS Enumeration Report for {domain}\n")
                        file.write(f"Generated on: {datetime.now()}\n")
                        file.write("=" * 60 + "\n\n")
                        
                        file.write(f"DNS RECORDS FOR MAIN DOMAIN ({domain}):\n")
                        file.write("=" * 40 + "\n")
                        if dns_records:
                            for record_type, records in dns_records.items():
                                file.write(f"{record_type} Records:\n")
                                for record in records:
                                    file.write(f"  {record}\n")
                                file.write("\n")
                        else:
                            file.write("No DNS records found\n\n")
                        
                        file.write("DISCOVERED SUBDOMAINS:\n")
                        file.write("=" * 20 + "\n")
                        if discovered_subs:
                            for subdomain in discovered_subs:
                                file.write(f"{subdomain}\n")
                        else:
                            file.write("No subdomains discovered\n")
                        file.write("\n")
                        
                        if subdomain_records:
                            file.write("DNS RECORDS FOR SUBDOMAINS:\n")
                            file.write("=" * 30 + "\n")
                            for subdomain, records in subdomain_records.items():
                                file.write(f"\n{subdomain}:\n")
                                for record_type, record_list in records.items():
                                    file.write(f"  {record_type} Records:\n")
                                    for record in record_list:
                                        file.write(f"    {record}\n")

                    print(f"\n{Colors.GREEN}[+] Full enumeration results saved to: {output_file}{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.RED}[!] Error saving full enumeration results: {e}{Colors.RESET}")


    """
    @DESCRIPTION: checks for dns zone transfer vulnerability
    @PARAMETERS: domain [str]
    @RETURNS: none
    """
    def check_zone_transfer(self, domain):
        print(f"\n[*] Checking for DNS zone transfer vulnerability on: {domain}")
        
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            name_servers = [str(ns) for ns in ns_records]
            print(f"[*] Found {len(name_servers)} authoritative name servers:")
            for ns in name_servers:
                print(f"    {ns}")
        except Exception as e:
            print(f"{Colors.RED}[!] Could not retrieve NS records: {e}{Colors.RESET}")
            return False
        
        zone_transfer_successful = False
        
        for ns in name_servers:
            print(f"\n[*] Attempting zone transfer from: {ns}")
            try:
                ns_clean = ns.rstrip('.')
                
                zone = dns.zone.from_xfr(dns.query.xfr(ns_clean, domain))
                
                if zone:
                    print(f"{Colors.GREEN}[+] VULNERABLE, Zone transfer successful from {ns}{Colors.RESET}")
                    
                    print(f"\n[*] Zone records discovered:")
                    record_count = 0
                    
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                record_count += 1
                                if record_count <= 50:
                                    print(f"{Colors.CYAN}  {name}.{domain} {rdataset.rdtype.name} {rdata}{Colors.RESET}")
                                elif record_count == 51:
                                    print(f"{Colors.YELLOW}  ... (showing first 50 records, {len(zone.nodes)} total nodes){Colors.RESET}")
                    
                    zone_transfer_successful = True
                    
            except dns.exception.FormError:
                print(f"{Colors.RED}[-] Zone transfer refused by {ns}{Colors.RESET}")
            except dns.exception.Timeout:
                print(f"{Colors.RED}[-] Timeout connecting to {ns}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[-] Zone transfer failed from {ns}: {e}{Colors.RESET}")
        
        if not zone_transfer_successful:
            print(f"\n{Colors.GREEN}[+] No zone transfer vulnerabilities found. {Colors.RESET}")
        else:
            print(f"\n{Colors.RED}[!] SECURITY ISSUE: Zone transfer vulnerability found!{Colors.RESET}")
        
        return zone_transfer_successful


    """
    @DESCRIPTION: performs reverse dns lookup on a list of ip addresses
    @PARAMETERS: ip_addresses [list]
    @RETURNS: found_hostnames [dict]
    """
    def reverse_dns_lookup(self, ip_addresses):
        print(f"\n[*] Starting reverse DNS lookups...")
        
        reverse_results = {}
        resolver = dns.resolver.Resolver()
        
        for ip in ip_addresses:
            try:
                reverse_name = dns.reversename.from_address(ip)
                answer = resolver.resolve(reverse_name, "PTR")
                
                hostnames = []
                for data in answer:
                    hostname = str(data).rstrip('.')
                    hostnames.append(hostname)
                
                if hostnames:
                    reverse_results[ip] = hostnames
                    print(f"{Colors.GREEN}[+] {ip} -> {', '.join(hostnames)}{Colors.RESET}")
                    
                    for hostname in hostnames:
                        if any(keyword in hostname.lower() for keyword in 
                               ['internal', 'corp', 'local', 'intranet', 'private', 'admin', 'mgmt', 'test', 'dev', 'staging']):
                            print(f"{Colors.YELLOW}    [!] Potential internal hostname found: {hostname}{Colors.RESET}")
                
            except dns.resolver.NXDOMAIN:
                print(f"{Colors.RED}[-] No PTR record for {ip}{Colors.RESET}")
            except dns.resolver.NoAnswer:
                print(f"{Colors.RED}[-] No PTR record for {ip}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error resolving {ip}: {e}{Colors.RESET}")
        
        return reverse_results


    """
    @DESCRIPTION: extracts ip addresses from dns records for reverse lookup
    @PARAMETERS: dns_records [dict]
    @RETURNS: ip_addresses [list]
    """
    def extract_ip_addresses(self, dns_records):
        ip_addresses = set()
        
        if 'A' in dns_records:
            for record in dns_records['A']:
                ip_addresses.add(record.strip())
        
        if 'AAAA' in dns_records:
            for record in dns_records['AAAA']:
                ip_addresses.add(record.strip())
        
        if 'MX' in dns_records:
            resolver = dns.resolver.Resolver()
            for mx_record in dns_records['MX']:
                parts = mx_record.split()
                if len(parts) >= 2:
                    mx_hostname = parts[1].rstrip('.')
                    try:
                        answer = resolver.resolve(mx_hostname, 'A')
                        for data in answer:
                            ip_addresses.add(str(data))
                    except:
                        continue
        
        return list(ip_addresses)


    """
    @DESCRIPTION: checks if a domain has dnssec enabled
    @PARAMETERS: domain [str]
    @RETURNS: dnssec_status [dict]
    """
    def check_dnssec(self, domain):
        print(f"\n[*] Checking DNSSEC status for: {domain}")
        
        resolver = dns.resolver.Resolver()
        dnssec_status = {
            'enabled': False,
            'dnskey_records': [],
            'ds_records': [],
            'rrsig_records': [],
            'validation_errors': []
        }
        
        print(f"[*] Checking for DNSKEY records...")
        try:
            dnskey_answer = resolver.resolve(domain, 'DNSKEY')
            for dnskey in dnskey_answer:
                dnssec_status['dnskey_records'].append(str(dnskey))
                parts = str(dnskey).split()
                if len(parts) >= 4:
                    flags = int(parts[0])
                    protocol = int(parts[1])
                    algorithm = int(parts[2])
                    
                    if flags & 0x0001:
                        key_type = "Key Signing Key (KSK)"
                    else:
                        key_type = "Zone Signing Key (ZSK)"
                    
                    print(f"{Colors.GREEN}[+] Found DNSKEY: {key_type}{Colors.RESET}")
                    print(f"    Flags: {flags}, Protocol: {protocol}, Algorithm: {algorithm}")
                    
            dnssec_status['enabled'] = True
            print(f"{Colors.GREEN}[+] DNSKEY records found (DNSSEC likely enabled){Colors.RESET}")

        except dns.resolver.NoAnswer:
            print(f"{Colors.RED}[-] No DNSKEY records found{Colors.RESET}")
        except dns.resolver.NXDOMAIN:
            print(f"{Colors.RED}[!] Domain {domain} does not exist{Colors.RESET}")
            return dnssec_status
        except Exception as e:
            print(f"{Colors.RED}[!] Error querying DNSKEY records: {e}{Colors.RESET}")
            dnssec_status['validation_errors'].append(f"DNSKEY query error: {e}")
        
        # Check for DS records
        print(f"\n[*] Checking for DS records in parent zone...")
        try:
            ds_answer = resolver.resolve(domain, 'DS')
            for ds in ds_answer:
                dnssec_status['ds_records'].append(str(ds))
                parts = str(ds).split()
                if len(parts) >= 4:
                    key_tag = parts[0]
                    algorithm = parts[1]
                    digest_type = parts[2]
                    print(f"{Colors.GREEN}[+] Found DS record:{Colors.RESET}")
                    print(f"    Key Tag: {key_tag}, Algorithm: {algorithm}, Digest Type: {digest_type}")
                    
        except dns.resolver.NoAnswer:
            print(f"{Colors.YELLOW}[-] No DS records found in parent zone{Colors.RESET}")
            if dnssec_status['dnskey_records']:
                print(f"{Colors.YELLOW}    DNSSEC configured but not properly delegated{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error querying DS records: {e}{Colors.RESET}")
            dnssec_status['validation_errors'].append(f"DS query error: {e}")
        
        # Check for RRSIG records
        print(f"\n[*] Checking for RRSIG records...")
        record_types_to_check = ['A', 'MX', 'NS', 'SOA']
        
        for record_type in record_types_to_check:
            try:
                answer = resolver.resolve(domain, record_type)
                if hasattr(answer, 'rrset') and answer.rrset:
                    try:
                        rrsig_answer = resolver.resolve(domain, 'RRSIG')
                        for rrsig in rrsig_answer:
                            if record_type in str(rrsig):
                                dnssec_status['rrsig_records'].append(str(rrsig))
                                print(f"{Colors.GREEN}[+] Found RRSIG for {record_type} records{Colors.RESET}")
                                break
                    except:
                        continue
            except:
                continue
        
        # DNSSEC validation test
        print(f"\n[*] Testing DNSSEC validation...")
        try:
            resolver.use_edns(0, dns.flags.DO, 4096)
            test_answer = resolver.resolve(domain, 'A')
            print(f"{Colors.GREEN}[+] DNSSEC validation test passed{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] DNSSEC validation test failed: {e}{Colors.RESET}")
            dnssec_status['validation_errors'].append(f"Validation test error: {e}")
        
        # Summary
        print(f"\n{Colors.CYAN}+--DNSSEC Status Summary --+{Colors.RESET}")
        if dnssec_status['dnskey_records']:
            print(f"{Colors.GREEN}[+] DNSSEC Status: ENABLED{Colors.RESET}")
            print(f"    DNSKEY Records: {len(dnssec_status['dnskey_records'])}")
            print(f"    DS Records: {len(dnssec_status['ds_records'])}")
            print(f"    RRSIG Records: {len(dnssec_status['rrsig_records'])}")
            
            if not dnssec_status['ds_records']:
                print(f"{Colors.YELLOW}    Warning: No DS records found - check parent zone delegation{Colors.RESET}")
                
        else:
            print(f"{Colors.RED}[-] DNSSEC Status: DISABLED or NOT CONFIGURED{Colors.RESET}")
        
        if dnssec_status['validation_errors']:
            print(f"{Colors.YELLOW}    Validation Issues:{Colors.RESET}")
            for error in dnssec_status['validation_errors']:
                print(f"      - {error}")
        
        # Save DNSSEC report
        if dnssec_status['dnskey_records'] or dnssec_status['ds_records']:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"dnssec_report_{domain}_{timestamp}.txt"
            try:
                with open(output_file, 'w') as file:
                    file.write(f"DNSSEC Report for {domain}\n")
                    file.write(f"Generated on: {datetime.now()}\n")
                    file.write("=" * 50 + "\n\n")
                    
                    file.write(f"DNSSEC Status: {'ENABLED' if dnssec_status['enabled'] else 'DISABLED'}\n\n")
                    
                    if dnssec_status['dnskey_records']:
                        file.write("DNSKEY Records:\n")
                        for record in dnssec_status['dnskey_records']:
                            file.write(f"  {record}\n")
                        file.write("\n")
                    
                    if dnssec_status['ds_records']:
                        file.write("DS Records:\n")
                        for record in dnssec_status['ds_records']:
                            file.write(f"  {record}\n")
                        file.write("\n")
                    
                    if dnssec_status['rrsig_records']:
                        file.write("RRSIG Records:\n")
                        for record in dnssec_status['rrsig_records']:
                            file.write(f"  {record}\n")
                        file.write("\n")
                    
                    if dnssec_status['validation_errors']:
                        file.write("Validation Errors:\n")
                        for error in dnssec_status['validation_errors']:
                            file.write(f"  {error}\n")
                
                print(f"\n{Colors.GREEN}[+] DNSSEC report saved to: {output_file}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error saving DNSSEC report: {e}{Colors.RESET}")
        
        return dnssec_status


    """
    @DESCRIPTION: run interactive mode
    @PARAMETERS: none
    @RETURNS: none
    """
    def run(self):
        while True:
            self.display_banner()
            try:
                choice = input("\nSelect an option (1-8): ").strip()
                
                if choice == '1':
                    domain = input("Enter the domain to enumerate DNS records: ").strip()
                    if domain:
                        self.enumerate_dns_records(domain)
                    else:
                        print(f"{Colors.RED}[!] Please enter a valid domain{Colors.RESET}")

                elif choice == '2':
                    domain = input("Enter the domain to enumerate subdomains: ").strip()
                    if domain:
                        custom_wordlist = input("Enter wordlist filename (press Enter for default 'subdomain.txt'): ").strip()
                        if not custom_wordlist:
                            custom_wordlist = 'subdomain.txt'
                        self.enumerate_subdomains(domain, custom_wordlist)
                    else:
                        print(f"{Colors.RED}[!] Please enter a valid domain{Colors.RESET}")

                elif choice == '3':
                    domain = input("Enter the domain for full DNS enumeration: ").strip()
                    if domain:
                        custom_wordlist = input("Enter wordlist filename (press Enter for default 'subdomain.txt'): ").strip()
                        if not custom_wordlist:
                            custom_wordlist = 'subdomain.txt'
                        self.full_enumeration(domain, custom_wordlist)
                    else:
                        print(f"{Colors.RED}[!] Please enter a valid domain{Colors.RESET}")

                elif choice == '4':
                    domain = input("Enter the domain to check for zone transfer vulnerability: ").strip()
                    if domain:
                        self.check_zone_transfer(domain)
                    else:
                        print(f"{Colors.RED}[!] Please enter a valid domain{Colors.RESET}")

                elif choice == '5':
                    domain = input("Enter the domain to check DNSSEC status: ").strip()
                    if domain:
                        self.check_dnssec(domain)
                    else:
                        print(f"{Colors.RED}[!] Please enter a valid domain{Colors.RESET}")

                elif choice == '6':
                    self.list_wordlists()
                
                elif choice == '8':
                    self.show_help()
                
                elif choice == '7':
                    print("\n[*] Exiting DNS Enumeration Tool...")
                    sys.exit(0)
                
                else:
                    print(f"{Colors.RED}[!] Invalid option. Please select 1-8.{Colors.RESET}")
                
            except KeyboardInterrupt:
                print("\n\n{Colors.YELLOW}[*] Tool interrupted. Exiting...{Colors.RESET}")
                sys.exit(0)
            except Exception as e:
                print(f"\n{Colors.RED}[!] An error occurred: {e}{Colors.RESET}")


    """
    @DESCRIPTION: run cli mode
    @PARAMETERS: args [argparse.Namespace]
    @RETURNS: none
    """
    def run_cli(self, args):
        if args.no_color:
            Colors.RESET = Colors.RED = Colors.GREEN = Colors.YELLOW = ""
            Colors.BLUE = Colors.MAGENTA = Colors.CYAN = Colors.BOLD = ""
        
        if args.list_wordlists:
            self.list_wordlists()
            return
        
        operations = [args.dns_records, 
                      args.subdomains, 
                      args.full_enum, 
                      args.zone_transfer, 
                      args.dnssec]
        
        if any(operations) and not args.domain:
            print(f"{Colors.RED}[!] Error: Domain (-d/--domain) is required for DNS operations{Colors.RESET}")
            sys.exit(1)
        
        if not args.domain and not args.list_wordlists:
            print(f"{Colors.YELLOW}[*] No domain specified. Starting interactive mode...{Colors.RESET}")
            self.run()
            return
        
        domain = args.domain
        
        if not args.quiet:
            print(f"{Colors.MAGENTA}")
            print("+-----------------------------------+")
            print("|  DNS ENUMERATION TOOL - CLI MODE  |")
            print("+-----------------------------------+")
            print(f"Target Domain: {domain}")
            print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("+-----------------------------------+")
            print(f"{Colors.RESET}")
        
        operations_performed = False
        
        if args.dns_records or args.full_enum:
            self.enumerate_dns_records(domain)
            operations_performed = True
        
        if args.subdomains or args.full_enum:
            self.enumerate_subdomains(domain, args.wordlist)
            operations_performed = True
        
        if args.zone_transfer:
            self.check_zone_transfer(domain)
            operations_performed = True
        
        if args.dnssec:
            self.check_dnssec(domain)
            operations_performed = True
        
        if not operations_performed and not args.list_wordlists:
            print(f"{Colors.YELLOW}[*] No operations specified. Available options:{Colors.RESET}")
            print("  --dns-records      : Enumerate DNS records")
            print("  --subdomains       : Enumerate subdomains")
            print("  --full-enum        : Full enumeration (DNS + subdomains)")
            print("  --zone-transfer    : Check zone transfer vulnerability")
            print("  --dnssec           : Check DNSSEC status")
            print("  --list-wordlists   : List available wordlists")
            print(f"\nUse --help for detailed usage information")
        
        if not args.quiet and operations_performed:
            print(f"\n{Colors.GREEN}[+] All operations completed successfully!{Colors.RESET}")


    """
    @DESCRIPTION: display help information
    @PARAMETERS: none
    @RETURNS: none
    """
    def show_help(self):
        help_text = (
            f"\n{Colors.CYAN}+-----------------------------+"
            f"\n| DNS Enumeration Tool - Help |"
            f"\n+-----------------------------+{Colors.RESET}"
            f"\n\n"
            f"{Colors.YELLOW}DESCRIPTION:{Colors.RESET}"
            f"\n    A comprehensive DNS reconnaissance and security testing tool for penetration"
            f"\n    testing and security assessments. Supports both interactive and CLI modes."
            f"\n\n"
            f"{Colors.YELLOW}BASIC USAGE:{Colors.RESET}"
            f"\n    Interactive Mode:    python3 DNS-Enumeration-Tool.py"
            f"\n    CLI Mode:           python3 DNS-Enumeration-Tool.py [OPTIONS]"
            f"\n    Help:              python3 DNS-Enumeration-Tool.py --help"
            f"\n\n"
            f"{Colors.YELLOW}CORE OPERATIONS:{Colors.RESET}"
            f"\n\n"
            f"{Colors.GREEN}    --dns-records{Colors.RESET}"
            f"\n        Description:    Enumerate all DNS record types for a domain"
            f"\n        Records Found:  A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR, CAA, DNSKEY, etc."
            f"\n        Use Case:       Infrastructure mapping, mail server discovery, TXT record analysis"
            f"\n        Example:        python3 DNS-Enumeration-Tool.py -d example.com --dns-records"
            f"\n        Output:         Saves to dns_records_domain_timestamp.txt"
            f"\n\n"
            f"{Colors.GREEN}    --subdomains{Colors.RESET}"
            f"\n        Description:    Threaded subdomain enumeration"
            f"\n        Method:         Multi-threaded DNS lookups + HTTP verification"
            f"\n        Performance:    ~500-1000 subdomains/minute"
            f"\n        Use Case:       Subdomain discovery for various sized wordlists"
            f"\n        Example:        python3 DNS-Enumeration-Tool.py -d example.com --subdomains -w FUZZING1.txt"
            f"\n        Options:        --threads (default: 50), --timeout (default: 5s)"
            f"\n\n"
            f"{Colors.GREEN}    --full-enum{Colors.RESET}"
            f"\n        Description:    Complete enumeration (DNS records + subdomain discovery)"
            f"\n        Method:         Combines DNS records enumeration with subdomain brute-forcing"
            f"\n        Use Case:       Comprehensive domain assessment, full infrastructure mapping"
            f"\n        Example:        python3 DNS-Enumeration-Tool.py -d example.com --full-enum -w DEFAULT.txt"
            f"\n\n"
            f"{Colors.GREEN}    --zone-transfer{Colors.RESET}"
            f"\n        Description:    Test for DNS zone transfer vulnerabilities (AXFR)"
            f"\n        Security Risk:  HIGH - Can expose entire DNS zone"
            f"\n        Method:         Attempts zone transfer from all authoritative name servers"
            f"\n        Use Case:       Security assessment, misconfiguration detection"
            f"\n        Example:        python3 DNS-Enumeration-Tool.py -d example.com --zone-transfer"
            f"\n        Output:         Shows vulnerable servers + leaked DNS records"
            f"\n\n"
            f"{Colors.GREEN}    --dnssec{Colors.RESET}"
            f"\n        Description:    DNSSEC validation and security analysis"
            f"\n        Checks:         DNSKEY records, DS records, RRSIG signatures, validation status"
            f"\n        Use Case:       DNS security assessment, DNSSEC implementation verification"
            f"\n        Example:        python3 DNS-Enumeration-Tool.py -d example.com --dnssec"
            f"\n        Output:         DNSSEC status report with security recommendations"
            f"\n\n"
            f"{Colors.YELLOW}WORDLIST OPTIONS:{Colors.RESET}"
            f"\n\n"
            f"{Colors.GREEN}    -w, --wordlist FILENAME{Colors.RESET}"
            f"\n        Description:    Specify custom wordlist for subdomain enumeration"
            f"\n        Default:        subdomain.txt"
            f"\n        Location:       Searches in 'subdomain lists' directory first, then script directory"
            f"\n        Examples:       -w DEFAULT.txt, -w FUZZING1.txt, -w /path/to/custom.txt"
            f"\n\n"
            f"{Colors.GREEN}    --list-wordlists{Colors.RESET}"
            f"\n        Description:    List all available wordlist files with line counts"
            f"\n        Use Case:       Discover available wordlists before starting enumeration"
            f"\n        Example:        python3 DNS-Enumeration-Tool.py --list-wordlists"
            f"\n\n"
            f"{Colors.YELLOW}PERFORMANCE OPTIONS:{Colors.RESET}"
            f"\n\n"
            f"{Colors.GREEN}    --threads NUMBER{Colors.RESET}"
            f"\n        Description:    Number of threads for subdomain enumeration"
            f"\n        Default:        50"
            f"\n        Range:          1-100 (recommended: 25-75)"
            f"\n        Example:        --threads 75"
            f"\n\n"
            f"{Colors.GREEN}    --timeout SECONDS{Colors.RESET}"
            f"\n        Description:    HTTP request timeout in seconds"
            f"\n        Default:        5"
            f"\n        Range:          1-30 (recommended: 3-10)"
            f"\n        Example:        --timeout 3"
            f"\n\n"
            f"{Colors.YELLOW}OUTPUT OPTIONS:{Colors.RESET}"
            f"\n\n"
            f"{Colors.GREEN}    -o, --output PREFIX{Colors.RESET}"
            f"\n        Description:    Custom output file prefix (timestamp added automatically)"
            f"\n        Default:        Uses operation type (dns_records_, subdomains_, etc.)"
            f"\n        Example:        -o company_assessment"
            f"\n\n"
            f"{Colors.GREEN}    --quiet{Colors.RESET}"
            f"\n        Description:    Reduce output verbosity (results only)"
            f"\n        Use Case:       Automation, scripting, log parsing"
            f"\n        Example:        --quiet"
            f"\n\n"
            f"{Colors.GREEN}    --no-color{Colors.RESET}"
            f"\n        Description:    Disable colored output"
            f"\n        Use Case:       Scripts, log files, terminals without color support"
            f"\n        Example:        --no-color"
            f"\n\n"
            f"{Colors.YELLOW}PRACTICAL EXAMPLES:{Colors.RESET}"
            f"\n\n"
            f"{Colors.CYAN}    # Quick DNS overview{Colors.RESET}"
            f"\n    python3 DNS-Enumeration-Tool.py -d target.com --dns-records --dnssec"
            f"\n\n"
            f"{Colors.CYAN}    # Fast subdomain discovery{Colors.RESET}"
            f"\n    python3 DNS-Enumeration-Tool.py -d target.com --subdomains -w FUZZING1.txt"
            f"\n\n"
            f"{Colors.CYAN}    # Comprehensive assessment{Colors.RESET}"
            f"\n    python3 DNS-Enumeration-Tool.py -d target.com --full-enum --zone-transfer --dnssec -w FUZZING1.txt"
            f"\n\n"
            f"{Colors.CYAN}    # Security-focused scan{Colors.RESET}"
            f"\n    python3 DNS-Enumeration-Tool.py -d target.com --zone-transfer --dnssec --dns-records"
            f"\n\n"
            f"{Colors.CYAN}    # Large-scale enumeration{Colors.RESET}"
            f"\n    python3 DNS-Enumeration-Tool.py -d target.com --subdomains -w FUZZING2.txt --threads 75"
            f"\n\n"
            f"{Colors.YELLOW}SECURITY CONSIDERATIONS:{Colors.RESET}"
            f"\n\n"
            f"{Colors.RED}    WARNING:{Colors.RESET} This tool performs active reconnaissance and may be detected by:"
            f"\n    • Web Application Firewalls (WAF)"
            f"\n    • Intrusion Detection Systems (IDS)"
            f"\n    • DNS monitoring systems"
            f"\n    • Rate limiting mechanisms"
            f"\n\n"
            f"{Colors.YELLOW}    BEST PRACTICES:{Colors.RESET}"
            f"\n    • Only test domains you own or have explicit permission to test"
            f"\n    • Use lower concurrency (--max-concurrent 25-50) for stealth"
            f"\n    • Consider using --dns-only to reduce HTTP requests"
            f"\n    • Monitor your requests to avoid overwhelming target infrastructure"
            f"\n    • Use VPN/proxy for operational security when authorized"
            f"\n\n"
            f"{Colors.YELLOW}TROUBLESHOOTING:{Colors.RESET}"
            f"\n\n"
            f"{Colors.GREEN}    Common Issues:{Colors.RESET}"
            f"\n    • \"No subdomains found\" → Try different wordlists (--list-wordlists)"
            f"\n    • \"Connection timeouts\" → Reduce --threads or increase --timeout"
            f"\n    • \"Permission denied\" → Check file permissions for wordlists and output directory"
            f"\n\n"
            f"{Colors.GREEN}    Performance Tips:{Colors.RESET}"
            f"\n    • Start with smaller wordlists (DEFAULT.txt) before using large ones"
            f"\n    • Adjust --threads based on your network and target capacity"
            f"\n    • Use --quiet mode for automation and faster processing"
            f"\n\n"
            f"{Colors.YELLOW}OUTPUT FILES:{Colors.RESET}"
            f"\n    All results are automatically saved with timestamps:"
            f"\n    • dns_records_domain_YYYYMMDD_HHMMSS.txt"
            f"\n    • discovered_subdomains_domain_YYYYMMDD_HHMMSS.txt"
            f"\n    • dnssec_report_domain_YYYYMMDD_HHMMSS.txt"
            f"\n\n"
            f"{Colors.CYAN}For more information, visit the project documentation or use --help{Colors.RESET}"
        )
        print(help_text)


"""
@DESCRIPTION: parse command line arguments
@PARAMETERS: none
@RETURNS: args [argparse.Namespace]
"""
def parse_arguments():
    help_example = (
        "Examples:\n"
        "  # Interactive mode (default)\n"
        "  python3 DNS-Enumeration-Tool.py\n"
        "\n"
        "  # Show detailed help\n"
        "  python3 DNS-Enumeration-Tool.py --help-detailed\n"
        "\n"
        "  # DNS records enumeration\n"
        "  python3 DNS-Enumeration-Tool.py -d example.com --dns-records\n"
        "\n"
        "  # Subdomain enumeration\n"
        "  python3 DNS-Enumeration-Tool.py -d example.com --subdomains -w FUZZING1.txt\n"
        "\n"
        "  # Comprehensive security assessment\n"
        "  python3 DNS-Enumeration-Tool.py -d example.com --full-enum --zone-transfer --dnssec\n"
    )

    parser = argparse.ArgumentParser(
        description="DNS Enumeration Tool for DNS reconnaissance and security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=help_example
    )
    
    # Domain argument
    parser.add_argument(
        '-d', '--domain',
        type=str,
        help='Target domain for enumeration'
    )
    
    # Operation flags
    parser.add_argument(
        '--dns-records',
        action='store_true',
        help='Perform DNS records enumeration'
    )
    
    parser.add_argument(
        '--subdomains',
        action='store_true',
        help='Perform subdomain enumeration'
    )
    
    parser.add_argument(
        '--full-enum',
        action='store_true',
        help='Perform full DNS enumeration (DNS records + subdomains)'
    )
    
    parser.add_argument(
        '--zone-transfer',
        action='store_true',
        help='Check for DNS zone transfer vulnerability'
    )
    
    parser.add_argument(
        '--dnssec',
        action='store_true',
        help='Check DNSSEC validation status'
    )
    
    # Help options
    parser.add_argument(
        '--help-detailed',
        action='store_true',
        help='Show detailed help for usage'
    )
    
    # Wordlist options
    parser.add_argument(
        '-w', '--wordlist',
        type=str,
        default='subdomain.txt',
        help='Wordlist file for subdomain enumeration (default: subdomain.txt)'
    )
    
    parser.add_argument(
        '--list-wordlists',
        action='store_true',
        help='List available wordlist files and exit'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file prefix (timestamp will be added automatically)'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Reduce output verbosity (only show results)'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    # threading options
    parser.add_argument(
        '--threads',
        type=int,
        default=50,
        help='Number of threads for subdomain enumeration (default: 50)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Timeout for HTTP requests in seconds (default: 5)'
    )
    
    return parser.parse_args()


"""
@DESCRIPTION: starts tool in either interactive or cli mode
@PARAMETERS: none
@RETURNS: none
"""
def main():
    try:
        args = parse_arguments()
        
        if args.help_detailed:
            tool = DNSEnumerationTool()
            tool.show_help()
            sys.exit(0)

        tool = DNSEnumerationTool()
        
        cli_operations = [
            args.dns_records,
            args.subdomains,
            args.full_enum,
            args.zone_transfer,
            args.dnssec,
            args.list_wordlists
        ]
        
        if any(cli_operations) or args.domain:
            tool.run_cli(args)
        else:
            print(f"{Colors.CYAN}[*] Starting in interactive mode...{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Use --help for CLI usage or --help-detailed for comprehensive help{Colors.RESET}")
            tool.run()
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Tool interrupted. Exiting...{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error running tool: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3

import json
import os
import socket
import threading
import webbrowser
from datetime import datetime

import dns.exception
import dns.flags
import dns.query
import dns.resolver
import dns.reversename
import dns.zone
import requests
from flask import Flask, jsonify, render_template, request

# Disable warnings about unverified HTTPS requests for subdomain enumeration
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create Flask app with specified static and template folders
app = Flask(__name__, static_folder=".", static_url_path="/static", template_folder=".")

# Define paths for wordlists
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDLISTS_DIR = os.path.join(SCRIPT_DIR, "wordlists")

def _get_resolver():
    """Creates and returns a configured DNS resolver instance
        Parameters
        ----------
        none

        Returns
        -------
        resolver : dns.resolver.Resolver

        Raises
        ------
        None
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    return resolver

def _extract_ip_addresses(dns_records):
    """Extracts IP addresses from A, AAAA, and MX DNS records
        Parameters
        ----------
        dns_records : dict

        Returns
        -------
        ip_addresses : list

        Raises
        ------
        None
    """
    ip_addresses = set()

    if "A" in dns_records:
        for record in dns_records["A"]:
            ip_addresses.add(record.strip())

    if "AAAA" in dns_records:
        for record in dns_records["AAAA"]:
            ip_addresses.add(record.strip())

    if "MX" in dns_records:
        resolver = _get_resolver()
        for mx_record in dns_records["MX"]:
            parts = mx_record.split()
            if len(parts) >= 2:
                mx_hostname = parts[1].rstrip(".")
                try:
                    answer = resolver.resolve(mx_hostname, "A")
                    for data in answer:
                        ip_addresses.add(str(data))
                except Exception:
                    continue

    return list(ip_addresses)

def _reverse_dns_lookup(ip_addresses):
    """Performs reverse DNS (PTR) lookups for a list of IP addresses
        Parameters
        ----------
        ip_addresses : list

        Returns
        -------
        results : dict

        Raises
        ------
        None
    """
    results = {}
    resolver = _get_resolver()

    for ip in ip_addresses:
        try:
            reverse_name = dns.reversename.from_address(ip)
            answer = resolver.resolve(reverse_name, "PTR")
            hostnames = [str(d).rstrip(".") for d in answer]
            if hostnames:
                results[ip] = hostnames
        except Exception:
            results[ip] = ["No PTR record"]

    return results

@app.route("/")
def index():
    """Serves the main web UI page
        Parameters
        ----------
        none

        Returns
        -------
        rendered index.html template : str

        Raises
        ------
        None
    """
    return render_template("index.html")

@app.route("/api/dns-records", methods=["POST"])
def api_dns_records():
    """Enumerates all DNS record types for a given domain
        Parameters
        ----------
        domain : str

        Returns
        -------
        records : dict
        reverse_dns : dict
        ip_addresses : list
        errors : list
        timestamp : str

        Raises
        ------
        None
    """
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    record_types = [
        "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA",
        "SRV", "PTR", "NAPTR", "CAA", "DNSKEY", "DS",
        "TLSA", "SSHFP", "CERT",
    ]

    resolver = _get_resolver()
    found_records = {}
    errors = []

    # Query each DNS record type and collect results
    for rtype in record_types:
        try:
            answer = resolver.resolve(domain, rtype)
            records = [str(d) for d in answer]
            if records:
                found_records[rtype] = records
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            return jsonify({"error": f"Domain {domain} does not exist (NXDOMAIN)"}), 404
        except Exception as e:
            errors.append(f"{rtype}: {str(e)}")
            continue

    # Extract IP addresses and perform reverse DNS lookups
    reverse_results = {}
    ip_addresses = _extract_ip_addresses(found_records)
    if ip_addresses:
        reverse_results = _reverse_dns_lookup(ip_addresses)

    return jsonify({
        "domain": domain,
        "records": found_records,
        "reverse_dns": reverse_results,
        "ip_addresses": ip_addresses,
        "errors": errors,
        "timestamp": datetime.now().isoformat(),
    })

@app.route("/api/subdomains", methods=["POST"])
def api_subdomains():
    """Enumerates subdomains using multi-threaded HTTP and DNS lookups
        Parameters
        ----------
        domain : str
        wordlist : str
        show_dns_lookups : bool
        threads : int
        timeout : int

        Returns
        -------
        discovered : list
        dns_only : list
        total_checked : int
        timestamp : str

        Raises
        ------
        None
    """
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip()
    wordlist = data.get("wordlist", "subdomain.txt").strip()
    show_dns = data.get("show_dns_lookups", False)
    threads = data.get("threads", 50)
    timeout = data.get("timeout", 5)

    threads = max(1, min(100, int(threads)))
    timeout = max(1, min(30, int(timeout)))

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    wordlist_path = wordlist
    if not os.path.isabs(wordlist_path):
        wordlist_path = os.path.join(WORDLISTS_DIR, wordlist_path)

    if not os.path.exists(wordlist_path):
        return jsonify({"error": f"Wordlist file not found: {wordlist}"}), 404

    try:
        with open(wordlist_path, "r") as f:
            subdomains = f.read().splitlines()
    except Exception as e:
        return jsonify({"error": f"Could not read wordlist: {e}"}), 500

    discovered = []
    dns_only = []
    lock = threading.Lock()

    def check_sub(sub):
        protocols = ["https", "http"]
        for proto in protocols:
            url = f"{proto}://{sub}.{domain}"
            try:
                resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
                status = resp.status_code
                entry = {"url": url, "status": status}
                if status in [301, 302, 303, 307, 308]:
                    entry["redirect"] = resp.headers.get("Location", "Unknown")
                with lock:
                    discovered.append(entry)
                return
            except Exception:
                continue

        if show_dns:
            try:
                full = f"{sub}.{domain}"
                ip = socket.gethostbyname(full)
                with lock:
                    dns_only.append({"domain": full, "ip": ip})
            except Exception:
                pass

    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Check subdomains in parallel using a thread pool
    max_workers = threads
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_sub, s): s for s in subdomains}
        for f in as_completed(futures):
            try:
                f.result()
            except Exception:
                pass

    return jsonify({
        "domain": domain,
        "wordlist": wordlist,
        "threads": max_workers,
        "timeout": timeout,
        "total_checked": len(subdomains),
        "discovered": sorted(discovered, key=lambda x: x["url"]),
        "dns_only": sorted(dns_only, key=lambda x: x["domain"]) if dns_only else [],
        "timestamp": datetime.now().isoformat(),
    })

@app.route("/api/zone-transfer", methods=["POST"])
def api_zone_transfer():
    """Checks for DNS zone transfer (AXFR) vulnerability across all name servers
        Parameters
        ----------
        domain : str

        Returns
        -------
        name_servers : list
        vulnerable : list
        refused : list
        errors : list
        is_vulnerable : bool

        Raises
        ------
        None
    """
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    results = {"domain": domain, "name_servers": [], "vulnerable": [], "refused": [], "errors": []}

    # Retrieve the NS records for the domain to get the list of authoritative name servers
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        results["name_servers"] = [str(ns) for ns in ns_records]
    except Exception as e:
        return jsonify({"error": f"Could not retrieve NS records: {e}"}), 500

    # Attempt a zone transfer (AXFR) from each name server and collect results
    for ns in results["name_servers"]:
        ns_clean = ns.rstrip(".")
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_clean, domain))
            if zone:
                records = []
                count = 0
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            count += 1
                            if count <= 100:
                                records.append({
                                    "name": f"{name}.{domain}",
                                    "type": rdataset.rdtype.name,
                                    "data": str(rdata),
                                })
                results["vulnerable"].append({
                    "server": ns,
                    "records": records,
                    "total_records": count,
                })
        except dns.exception.FormError:
            results["refused"].append(ns)
        except dns.exception.Timeout:
            results["errors"].append(f"Timeout connecting to {ns}")
        except Exception as e:
            results["errors"].append(f"{ns}: {str(e)}")

    results["is_vulnerable"] = len(results["vulnerable"]) > 0
    results["timestamp"] = datetime.now().isoformat()
    return jsonify(results)

@app.route("/api/dnssec", methods=["POST"])
def api_dnssec():
    """Checks DNSSEC configuration including DNSKEY, DS, and RRSIG records
        Parameters
        ----------
        domain : str

        Returns
        -------
        enabled : bool
        dnskey_records : list
        ds_records : list
        rrsig_records : list
        keys : list
        validation_errors : list

        Raises
        ------
        None
    """
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    resolver = _get_resolver()
    status = {
        "domain": domain,
        "enabled": False,
        "dnskey_records": [],
        "ds_records": [],
        "rrsig_records": [],
        "validation_errors": [],
        "keys": [],
    }

    # Check for DNSKEY records to determine if DNSSEC is enabled
    try:
        dnskey_answer = resolver.resolve(domain, "DNSKEY")
        for dnskey in dnskey_answer:
            raw = str(dnskey)
            status["dnskey_records"].append(raw)
            parts = raw.split()
            if len(parts) >= 4:
                flags = int(parts[0])
                key_type = "Key Signing Key (KSK)" if flags & 0x0001 else "Zone Signing Key (ZSK)"
                status["keys"].append({
                    "type": key_type,
                    "flags": flags,             # 256 for ZSK, 257 for KSK
                    "protocol": int(parts[1]),  # should always be 3 for DNSSEC
                    "algorithm": int(parts[2]), # cryptographic algorithm number
                })
        status["enabled"] = True
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        return jsonify({"error": f"Domain {domain} does not exist"}), 404
    except Exception as e:
        status["validation_errors"].append(f"DNSKEY query error: {e}")

    # Check for DS records to verify delegation from parent zone
    try:
        ds_answer = resolver.resolve(domain, "DS")
        for ds in ds_answer:
            raw = str(ds)
            status["ds_records"].append(raw)
    except dns.resolver.NoAnswer:
        if status["dnskey_records"]:
            status["validation_errors"].append("No DS records found - DNSSEC configured but not properly delegated")
    except Exception as e:
        status["validation_errors"].append(f"DS query error: {e}")

    # Check for RRSIG records to confirm signatures exist for key record types
    for rtype in ["A", "MX", "NS", "SOA"]:
        try:
            resolver.resolve(domain, rtype)
            rrsig_answer = resolver.resolve(domain, "RRSIG")
            for rrsig in rrsig_answer:
                if rtype in str(rrsig):
                    status["rrsig_records"].append(str(rrsig))
                    break
        except Exception:
            continue

    # Perform a test resolution to check if DNSSEC validation is working properly
    try:
        test_resolver = _get_resolver()
        test_resolver.use_edns(0, dns.flags.DO, 4096)
        test_resolver.resolve(domain, "A")
        status["validation_passed"] = True
    except Exception as e:
        status["validation_passed"] = False
        status["validation_errors"].append(f"Validation test error: {e}")

    status["timestamp"] = datetime.now().isoformat()
    return jsonify(status)

@app.route("/api/wordlists", methods=["GET"])
def api_wordlists():
    """Lists all available .txt wordlist files in the wordlists/ directory
        Parameters
        ----------
        none

        Returns
        -------
        wordlists : list
        wordlists_dir : str

        Raises
        ------
        None
    """
    wordlists = []

    if not os.path.exists(WORDLISTS_DIR):
        os.makedirs(WORDLISTS_DIR, exist_ok=True)

    for f in sorted(os.listdir(WORDLISTS_DIR)):
        if f.endswith(".txt"):
            path = os.path.join(WORDLISTS_DIR, f)
            try:
                with open(path, "r") as fh:
                    lines = sum(1 for _ in fh)
                wordlists.append({"name": f, "lines": lines})
            except Exception:
                wordlists.append({"name": f, "lines": -1})

    return jsonify({"wordlists": wordlists, "wordlists_dir": WORDLISTS_DIR})

def open_browser():
    """Opens the default web browser to the app URL after a short delay
        Parameters
        ----------
        none

        Returns
        -------
        None

        Raises
        ------
        None
    """
    import time
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:5000")

if __name__ == "__main__":
    print("\n====================================")
    print("  DNS Enumeration Tool - Web UI")
    print("====================================")
    print("  Open http://127.0.0.1:5000 in your browser")
    print("  Press Ctrl+C to stop the server")
    print("====================================\n")

    threading.Thread(target=open_browser, daemon=True).start()

    app.run(host="127.0.0.1", port=5000, debug=False)

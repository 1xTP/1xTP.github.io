---
layout: post
title: ARGUS - Recon Automation Tool
date: 2026-07-03
pid: "0213"
category: "Custom-Tools"
language: "Python"
description: "A Python script to automate the initial recon process of capture the flag challenges."
tags: [Networking, Automation]
---
### Overview
ARGUS is a Python-based reconnaissance tool I built to automate the initial enumeration phase of Capture The Flag (CTF) challenges. It wraps Nmap, Dirsearch, and Ffuf into a unified workflow, managing execution, real-time output parsing, and local DNS routing.

### The Problem
During typical CTF workflows, the first couple of minutes are largely identical. I would run a port scan, map the IP to a local hosts file, and kick off directory and virtual host enumeration. Typing the exact same commands and manually managing DNS entries for every target creates unnecessary friction.

I wrote ARGUS to handle this setup phase automatically. While heavy automated scanners exist, I wanted a lightweight, dependency-free script made specifically for my workflow that outputs clean, actionable data without massive log files.

### Design Decisions & Architecture
**State-Aware Execution**
I originally wanted to thread the tools to make the scans insanely fast, but blasting a box with concurrent network scans just gets you rate-limited or causes you to miss open ports. Instead, I made ARGUS linear but smart. It runs Nmap first, checks if web ports (like 80 or 443) are actually open, and if they aren't, it completely skips the Dirsearch and Ffuf phases so I don't waste time waiting on dead ends.

**Real-Time Streaming & Parsing**
Trying to parse raw terminal output with string splitting is a nightmare waiting to break. I swapped Nmap over to output XML and parsed it natively with Python's `xml.etree.ElementTree`.

But for Dirsearch and Ffuf, waiting for a 20,000-word list to finish just to see the results completely defeats the point of a terminal UI. I ripped out the blocking subprocesses and set up `subprocess.Popen` to stream the output in real-time. Now, the second a directory or subdomain gets hit, it prints to the screen. I also dumped all the junk status codes (like 500s) straight into Dirsearch's native `-x` filter so Python doesn't even have to process the noise.

**Safe `/etc/hosts` Management**
Manually editing `/etc/hosts` every time I find a new virtual host breaks my workflow, so ARGUS checks and routes domains automatically before and after the scans. I originally used a raw Bash `sed` command for this, but that's messy and opens the door for shell injection. Now, the script handles the logic safely in memory. It reads the hosts file, lines up the new routes, writes a temporary file, and safely copies it over using a strict `subprocess.run` list with `sudo`.

**Artifact Cleanup**
Dirsearch refuses to stop dropping a `reports/` folder in my working directory—the built-in command-line flag to disable it is literally broken. I like to keep my CTF project folders clean and leave no trace behind, so I threw a `cleanup()` method at the end of the script to automatically sweep the directory and trash those stray artifacts.

### Usage
**Prerequisites**
You need the following installed and accessible in your path:
- `nmap`
- `dirsearch`
- `ffuf`
- SecLists

**Execution**
```
# Standard Execution (Defaults to HTTPS and standard SecLists path)
./main.py -i 10.10.10.10 -d example.htb

# Force HTTP Execution and pass a custom wordlist
./main.py -i 10.10.10.10 -d example.htb -k -w /path/to/custom_wordlist.txt
```

### The Code
```
#!/usr/bin/env python3
import sys
import os
import shutil
import subprocess
import argparse
import threading
import time
import xml.etree.ElementTree as ET

PRIMARY = '\033[96m'
SUCCESS = '\033[92m'
WARNING = '\033[93m'
DANGER = '\033[91m'
MUTED = '\033[90m'
FOREGROUND = '\033[97m'
RESET = '\033[0m'

class ArgusScanner:
    def __init__(self, target_ip, target_domain, use_http=True, wordlist=None):
        self.target_ip = target_ip
        self.target_domain = target_domain.replace("http://", "").replace("https://", "")
        self.protocol = "http" if use_http else "https"
        self.target_url = f"{self.protocol}://{self.target_domain}"
        self.wordlist = wordlist or "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"
        
        self.web_ports_open = False
        self.discovered_subdomains = []
        self.missing_tools = []

    def log(self, text, color=FOREGROUND):
        print(f"{color}{text}{RESET}")

    def log_header(self, text):
        print(f"\n{PRIMARY}{text}{RESET}")
        print(f"{PRIMARY}{'—' * 50}{RESET}")

    def _spinner(self, event, message):
        spinner_chars = ['|', '/', '-', '\\']
        idx = 0
        while not event.is_set():
            sys.stdout.write(f"\r{PRIMARY}[{spinner_chars[idx]}]{RESET} {MUTED}{message}{RESET}")
            sys.stdout.flush()
            idx = (idx + 1) % len(spinner_chars)
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * (len(message) + 6) + '\r')
        sys.stdout.flush()

    def check_tools(self):
        required_tools = ["nmap", "dirsearch", "ffuf"]
        for tool in required_tools:
            if shutil.which(tool) is None:
                self.missing_tools.append(tool)

        if self.missing_tools:
            self.log(f"[!] Missing dependencies: {', '.join(self.missing_tools)}", DANGER)
            sys.exit(1)

        if not os.path.exists(self.wordlist):
            self.log(f"[!] Wordlist not found at {self.wordlist}", DANGER)
            sys.exit(1)

    def stream_command(self, cmd):
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )
        for line in process.stdout:
            yield line
        process.wait()

    def nmap(self):
        self.log_header(f"Scanning Ports on {self.target_ip}")
        cmd = ["nmap", "-sC", "-sV", self.target_ip, "-oX", "-"]
        
        done_event = threading.Event()
        spinner_thread = threading.Thread(target=self._spinner, args=(done_event, "Running Nmap..."))
        spinner_thread.start()

        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
            xml_output = result.stdout
        except subprocess.CalledProcessError:
            self.log("\n[!] Nmap scan failed.", DANGER)
            return
        finally:
            done_event.set()
            spinner_thread.join()

        try:
            root = ET.fromstring(xml_output)
            for host in root.findall('host'):
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_id = port.get('portid')
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else "unknown"
                        
                        if service_name in ['http', 'https', 'http-alt'] or port_id in ['80', '443', '8080', '3000']:
                            self.web_ports_open = True

                        self.log(f" [+] Port {port_id}/tcp : {service_name}", PRIMARY)
        except ET.ParseError:
            self.log("[!] Failed to parse Nmap XML output.", DANGER)

    def dirsearch(self):
        if not self.web_ports_open:
            self.log("\n[-] No web ports detected. Skipping Dirsearch.", MUTED)
            return

        self.log_header(f"Fuzzing Directories on {self.target_url}")
        cmd = ["dirsearch", "-u", self.target_url, "--no-color", "-q", "-x", "500,502,503,404,400"]

        for line in self.stream_command(cmd):
            clean_line = line.strip()
            if clean_line.startswith("[") and "]" in clean_line:
                parts = clean_line.split(" - ", 2)
                if len(parts) >= 2:
                    status_code = parts[0].split(" ")[-1]
                    size = parts[1].strip()
                    url_info = parts[2] if len(parts) > 2 else ""

                    color = SUCCESS if status_code.startswith('2') else WARNING if status_code.startswith(('3', '4')) else MUTED
                    print(f" {color}[{status_code}]{RESET} {MUTED}[{size:>7}]{RESET} {FOREGROUND}{url_info}{RESET}")

    def ffuf(self):
        if not self.web_ports_open:
            self.log("\n[-] No web ports detected. Skipping Ffuf.", MUTED)
            return

        self.log_header(f"Fuzzing Subdomains on {self.target_domain}")
        cmd = ["ffuf", "-u", self.target_url, "-H", f"Host: FUZZ.{self.target_domain}", "-w", self.wordlist, "-ac"]

        for line in self.stream_command(cmd):
            clean_line = line.strip()
            if "[Status:" in clean_line:
                parts = clean_line.split("[Status:")
                subdomain = parts[0].strip()
                
                stats_block = parts[1].split(",")
                status_code = stats_block[0].strip()

                full_domain = f"{subdomain}.{self.target_domain}"
                self.discovered_subdomains.append(full_domain)
                
                color = SUCCESS if status_code.startswith('2') else WARNING
                print(f" {color}[+]{RESET} {FOREGROUND}{full_domain:<30}{RESET} {MUTED}[Status: {status_code}]{RESET}")

    def manage_hosts_file(self):
        domains_to_check = [self.target_domain] + self.discovered_subdomains
        missing_domains = []

        try:
            with open('/etc/hosts', 'r') as f:
                hosts_content = f.read()
                for domain in domains_to_check:
                    if domain not in hosts_content:
                        missing_domains.append(domain)
        except Exception as e:
            self.log(f"\n[!] Could not read /etc/hosts: {e}", DANGER)
            return

        if not missing_domains:
            return

        self.log_header("Hosts File Management")
        for d in missing_domains:
            self.log(f" - Missing: {d}", MUTED)
        
        prompt = f"\n{PRIMARY}[?] Add {len(missing_domains)} domain(s) to /etc/hosts? (Requires sudo) [Y/n]: {RESET}"
        choice = input(prompt).strip().lower()
        
        if choice not in ('', 'y'):
            self.log("[-] Skipping /etc/hosts modification.", MUTED)
            return

        try:
            with open('/etc/hosts', 'r') as f:
                lines = f.readlines()

            ip_found = False
            new_lines = []
            new_domains_str = ' '.join(missing_domains)

            for line in lines:
                if line.strip().startswith(self.target_ip):
                    line = line.rstrip() + f" {new_domains_str}\n"
                    ip_found = True
                new_lines.append(line)

            if not ip_found:
                new_lines.append(f"{self.target_ip}\t{new_domains_str}\n")

            temp_path = "/tmp/argus_hosts_tmp"
            with open(temp_path, 'w') as f:
                f.writelines(new_lines)
            
            subprocess.run(["sudo", "cp", temp_path, "/etc/hosts"], check=True)
            subprocess.run(["rm", temp_path], check=True)

            self.log("[+] Successfully updated /etc/hosts", SUCCESS)
        except Exception as e:
            self.log(f"[!] Failed to update /etc/hosts: {e}", DANGER)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARGUS - Refactored Recon Tool")
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist")
    
    args = parser.parse_args()

    scanner = ArgusScanner(
        target_ip=args.ip,
        target_domain=args.domain,
        wordlist=args.wordlist
    )
    
    scanner.check_tools()
    scanner.manage_hosts_file()
    scanner.nmap()
    scanner.dirsearch()
    scanner.ffuf()
    scanner.manage_hosts_file()
```
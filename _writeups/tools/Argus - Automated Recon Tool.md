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
ARGUS is a Python script I built to automate the initial reconnaissance phase of Capture The Flag (CTF) challenges. It wraps Nmap, Dirsearch, and Ffuf into a single workflow, handling the execution, output filtering, and local DNS routing so I don't have to.

### Why I Built This
After playing HackTheBox for a while, I realized I was spending the first 5 minutes of every single box typing the exact same commands. I got bored and slightly annoyed with the repetitive setup phase, so I wrote this to handle the busywork.

Originally, my plan was to thread the tools and make the scans insanely fast. I quickly realized why that doesn't work well in practice. Blasting a box with concurrent network scans just leads to rate limits, dropped connections, and missed ports. Because of that, I moved away from raw execution speed and instead focused on automating the workflow and keeping the parsed data accurate.

### How It Works
I structured this using an Object-Oriented approach to keep things modular and easy to read.

**Execution & Data Filtering** 
I initially tried streaming the output while the tools ran, but progress bars and terminal updates completely broke my parsing logic. To fix this, I switched to using `subprocess.run()` for batch processing. The script waits for the network tool to finish its scan completely, grabs the raw output, filters out the junk, and prints only what I actually need. To keep the terminal from looking dead during a long Nmap scan, I threw in a native ASCII spinner on a background thread.

**Automated /etc/hosts Management** 
Having to open a new terminal tab to manually map discovered subdomains (like `dev.enigma.htb`) to the target IP was the most annoying part of the initial recon process. ARGUS reads the local `/etc/hosts` file directly. If it sees that the primary domain or any newly discovered Ffuf subdomains are missing, it prompts to add them.

Instead of making the file a mess by appending duplicate lines for the same IP, it uses a simple `sed` command to find the exact line starting with the target IP and adds the new subdomains onto the end of it:
```
sudo sed -i '/^10.10.10.10/ s/$/ dev.enigma.htb/' /etc/hosts
```

**Theming and UI**
I got tired of hardcoding ANSI color codes into every print statement, so I set up a few global variables at the top of the file (`PRIMARY`, `FOREGROUND`, `MUTED`, `DANGER`). This makes it easy to highlight open ports and mute standard service information without having a mess of escape characters buried in the parsing logic.

### Usage
**Prerequisites** You need the following installed and accessible in your path:
- `nmap`
- `dirsearch`
- `ffuf`
- SecLists (specifically the `subdomains-top1million-20000.txt` wordlist)

If you decided to move/install the SecLists dictionary outside of `/usr/share/wordlists/`, be sure to change the directory in the script accordingly.

**Execution**
```
# Standard Execution (Defaults to HTTPS)
./main.py -i 10.10.10.10 -d example.htb

# Force HTTP Execution
./main.py -i 10.10.10.10 -d example.htb -k
```

### The Script
```python
#!/usr/bin/env python3
import sys
import os
import shutil
import subprocess
import argparse
import threading
import time

PRIMARY = '\033[96m'     # Bright Cyan (Headers, Spinners, Highlights)
FOREGROUND = '\033[97m'  # Bright White (Main Output Text)
MUTED = '\033[37m'       # Light Grey (Secondary/Boring Info)
DANGER = '\033[91m'      # Bright Red (Errors/Failures)
RESET = '\033[0m'        # Terminal Default

class ArgusScanner:
    def __init__(self, targetIP, targetDomain, useHttp):
        self.targetIP = targetIP
        self.targetDomain = targetDomain.replace("http://", "").replace("https://", "")
        self.protocol = "http" if useHttp else "https"
        self.targetURL = f"{self.protocol}://{self.targetDomain}"
        self.targetWordlist = "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"

    def printHeader(self, text):
        print(f"\n{PRIMARY}{text}{RESET}")
        print(f"{PRIMARY}{'—' * 50}{RESET}")

    def printFooter(self):
        print(f"{PRIMARY}{'—' * 50}{RESET}")

    def printData(self, text, highlight=False, muted=False):
        if highlight:
            color = PRIMARY
        elif muted:
            color = MUTED
        else:
            color = FOREGROUND
            
        print(f"{color}{text}{RESET}")

    def printError(self, text):
        print(f"{DANGER}[!] {text}{RESET}")
        sys.exit(1)

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

    def checkTools(self):
        requiredDictionary = "/usr/share/wordlists/SecLists"
        requiredTools = ["nmap", "dirsearch", "ffuf"]

        for tool in requiredTools:
            if shutil.which(tool) is None:
                self.printError(f"Install the following tool: {tool}")

        if not os.path.exists(requiredDictionary):
            self.printError(f"SecList wordlist directory does not exist at {requiredDictionary}.")

    def getMissingDomains(self, domains):
        missing = []
        try:
            with open('/etc/hosts', 'r') as f:
                hostsContent = f.read()
            
            for domain in domains:
                if domain not in hostsContent:
                    missing.append(domain)
        except Exception as e:
            self.printError(f"Could not read /etc/hosts: {e}")
            
        return missing

    def addToHosts(self, domains):
        missing = self.getMissingDomains(domains)
        
        if not missing:
            return

        self.printHeader("Hosts File Management")
        for d in missing:
            self.printData(f" - Missing from /etc/hosts: {d}", muted=True)
        
        try:
            prompt = f"\n{PRIMARY}[?] Add {len(missing)} domain(s) to /etc/hosts? (Requires sudo) [Y/n]: {RESET}"
            choice = input(prompt).strip().lower()
            
            if choice == '' or choice == 'y':
                newDomains = ' '.join(missing)
                
                with open('/etc/hosts', 'r') as f:
                    ipExists = any(line.strip().startswith(self.targetIP) for line in f)

                if ipExists:
                    cmd = f"sudo sed -i '/^{self.targetIP}/ s/$/ {newDomains}/' /etc/hosts"
                else:
                    entry = f"{self.targetIP}\t{newDomains}"
                    cmd = f"echo '{entry}' | sudo tee -a /etc/hosts > /dev/null"
                    
                subprocess.run(cmd, shell=True, check=True)
                
                self.printData(f"[+] Successfully updated /etc/hosts", highlight=True)
            else:
                self.printData("[-] Skipping /etc/hosts modification.", muted=True)
        except Exception as e:
            self.printError(f"Failed to edit /etc/hosts: {e}")

    def executeCommand(self, cmd, loadingMessage):
        done_event = threading.Event()
        spinner_thread = threading.Thread(target=self._spinner, args=(done_event, loadingMessage))
        
        spinner_thread.start()
        
        try:
            rawOutput = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output = rawOutput.stdout
        except subprocess.CalledProcessError as e:
            output = e.stdout
        finally:
            done_event.set()
            spinner_thread.join()

        return output

    def startNmap(self):
        cmd = ["nmap", "-sCV", self.targetIP, "--min-rate", "5000"]
        output = self.executeCommand(cmd, f"Running Nmap against {self.targetIP}...")

        self.printHeader("Nmap Results")

        try:
            ports = output.split("VERSION\n")[1].split("Service Info:")[0]
            for line in ports.strip().split('\n'):
                cleanLine = line.lstrip() 
                
                if cleanLine and cleanLine[0].isdigit():
                    self.printData(f" - {cleanLine}", highlight=True)
                else:
                    self.printData(f"   {cleanLine}", muted=True)
        except IndexError:
            print(f"{DANGER}[!] Could not parse Nmap output table.{RESET}")

        self.printFooter()

    def startDirsearch(self):
        cmd = ["dirsearch", "-u", self.targetURL, "--no-color", "-q"]
        output = self.executeCommand(cmd, f"Running Dirsearch against {self.targetURL}...")

        self.printHeader("Dirsearch Results")

        for line in output.splitlines():
            cleanLine = line.strip()

            if cleanLine.startswith("[") and "]" in cleanLine[9:11]:
                self.printData(f" {cleanLine}")

        self.printFooter()

    def startFfuf(self):
        cmd = ["ffuf", "-u", self.targetURL, "-H", f"Host: FUZZ.{self.targetDomain}", "-w", self.targetWordlist, "-ac", "-s"]
        output = self.executeCommand(cmd, f"Running Ffuf on {self.targetDomain}...")

        self.printHeader("Ffuf Results")

        lines = [line for line in output.splitlines() if line.strip()]
        foundSubdomains = []
        
        for line in lines:
            self.printData(line)
            fullDomain = f"{line}.{self.targetDomain}"
            foundSubdomains.append(fullDomain)

        self.printFooter()

        if foundSubdomains:
            self.addToHosts(foundSubdomains)

    def runScanner(self):
        self.checkTools()
        self.addToHosts([self.targetDomain])

        self.startNmap()
        self.startDirsearch()
        self.startFfuf()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="ARGUS - Automated Reconnaissance & Enumeration Suite", 
        epilog="Example: ./main.py -i 10.10.10.10 -d enigma.htb -k | Author: 1xTP"
    )
    
    parser.add_argument("-i", "--ip", required=True, help="The IP address of the target (e.g, 10.10.10.10)")
    parser.add_argument("-d", "--domain", required=True, help="The assumed or known domain of the target (e.g, example.com)")
    parser.add_argument("-k", "--http", required=False, action="store_true", help="Force HTTP instead of HTTPS")
    
    args = parser.parse_args()

    scanner = ArgusScanner(args.ip, args.domain, args.http)
    scanner.runScanner()
```
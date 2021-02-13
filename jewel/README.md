# Jewel

## nmap -T3 -A -p- -o jewel.nmap 10.10.10.211

[Nmap scan result][1]

Looking at the scan result there are two web servers one on port 8000 that seems a git repository, and one on port 8080 that is a blog.

## Git page

Inside the git repository there is a file bd.sql in which there are two account with two hashes

`bill:$2a$12$uhUssB8.HFpT4XpbhclQU.Oizufehl9qqKtmdxTXetojn2FcNncJW` and `jennifer:$2a$12$ik.0o.TGRwMgUmyOR.Djzuyb/hjisgk2vws1xYC/hxw8M1nFk0MQy` cracking the hashes seems not produce any result.

for better performance while cracking use hashcat with gpu support `hashcat.bin -m 3200 -a 0 -w 3 hash.txt rockyou.txt.gz`

Looking into the Gemfile we can see that the "BLOG" use Rails version 5.2.2.1 which is vulnerable to [CVE-2020-8165][4] in fact the update username function has `raw: true` parameter set.

Using [exploit][2] we can get the user flag from bill.


## Priv escalation

`python3 -c "import pty;pty.spawn('/bin/bash')"`

Inside the bill's home there is a file `.google_authenticator` -> `2UQI3R52WFCLE6JTLDCSJYMJH4` 

After a very long session john found a password for bill ***bill:spongebob*** that we can use for `sudo`

sudo asks for a verifaction code so we need to add the code printed before on a mobile google_authenticator app and sync the time to get a valid code

```raw
sudo -l 
[sudo] password for bill: spongebob

Verification code: 599509

Matching Defaults entries for bill on jewel:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    insults

User bill may run the following commands on jewel:
    (ALL : ALL) /usr/bin/gem
```

[getting root via gem][3]

[//]: #links
[1]: jewel.nmap
[2]: ex.py
[3]: https://gtfobins.github.io/gtfobins/gem/#sudo
[4]: https://github.com/masahiro331/CVE-2020-8165

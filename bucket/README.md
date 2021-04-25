# bucket

## nmap scan

[Scan Results][1]

## Bucket Advertising Platform

Looking at the source of the site we see some reference to a S3 server `s3.bucket.htb`

[Dir Buster bucket.htb][2]
[Dir Buster s3.bucket.htb][3] looking at the directory found we see a DynamoDB web shell. we can use the `aws-cli` suite to dig inside the db.

## AWS Cli

Search for tables entries:

`aws dynamodb list-tables --endpoint-url http://s3.bucket.htb` -> `users`
`aws dynamodb scan --table-name users --endpoint-url http://s3.bucket.htb` ->

```raw
PASSWORD        Management@#1@#
USERNAME        Mgmt
PASSWORD        Welcome123!
USERNAME        Cloudadm
PASSWORD        n2vM-<_K_Q:.Aa2
USERNAME        Sysadm
```

so we have some accounts: try to login via ssh doesn't work

Continue searching intresting files inside the s3 bucket.

`aws s3 ls --endpoint-url http://s3.bucket.htb/` -> `adserver`
`aws s3 ls s3://adserver --endpoint-url http://s3.bucket.htb/` Inside this bucket there is an `index.html` file and a images directory, that resembles the website structure, S3 in fact can be used as webhost also, so we can upload a [php reverse shell][4] inside the bucket.

Upload the shell via

`aws s3 cp exploit/rev.php s3://adserver/rev.php --endpoint-url http://s3.bucket.htb`

After uploaded there a small time window in wich the reverse shell go online and get deleted by the server reset, so can be usefull to use `curl` to start the reverse shell. We can also automate the deploy with a [bash script][5]

## www-data

First of all spawn a bash shell:

`python3 -c "import pty;pty.spawn('/bin/bash')"`

Doing an ls of /home directory we can see there is a user roy, maybe we can use a password found previusly to login via ssh with user roy

And we have user flag: ***roy:n2vM-<_K_Q:.Aa2***

## Roy to Root

[Linpeas scan][6]

As suggested by linpeas we can try to get root via [runc][9] but doesn't work

looking at some intresting file inside the linpeas result seems that there is an other website in `/var/www/bucket-app/` that listen on port 8000. This site does something weird:

```php
<?php
require 'vendor/autoload.php';
use Aws\DynamoDb\DynamoDbClient;
if($_SERVER["REQUEST_METHOD"]==="POST") {
        if($_POST["action"]==="get_alerts") {
                date_default_timezone_set('America/New_York');
                $client = new DynamoDbClient([
                        'profile' => 'default',
                        'region'  => 'us-east-1',
                        'version' => 'latest',
                        'endpoint' => 'http://localhost:4566'
                ]);

                $iterator = $client->getIterator('Scan', array(
                        'TableName' => 'alerts',
                        'FilterExpression' => "title = :title",
                        'ExpressionAttributeValues' => array(":title"=>array("S"=>"Ransomware")),
                ));

                foreach ($iterator as $item) {
                        $name=rand(1,10000).'.html';
                        file_put_contents('files/'.$name,$item["data"]);
                }
                passthru("java -Xmx512m -Djava.awt.headless=true -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf");
        }
}
else
{
?>
```

Seems that when the server recieves a POST request with payload `action` equals to `get_alerts` search inside `DynamoDB` for a table `alerts` and filter any result that have as `title`->`{"S":"Ransomware}`, than put the content `data` inside a file and convert it in an pdf using `pd4ml` java package. The `pd4ml` is an HTML to PDF converter.

During our first analisys we didn't found any `alerts` table inside DynamoDB so we can create the table with an entry that contains malicious html in order to steal the root ssh key.

[Local Root exploit][7]
[Remote Root exploit][8]

And we are done.

[//]: #links
[1]: nmap/bucket.nmap
[2]: bucket-dir.txt
[3]: s3.bucket-dir.txt
[4]: exploit/rev.php
[5]: exploit/deploy.sh
[6]: linpeas.txt
[7]: exploit/root_exploit.sh
[8]: exploit/root_exploit2.sh
[9]: https://book.hacktricks.xyz/linux-unix/privilege-escalation/runc-privilege-escalation

![htbbadge](https://www.hackthebox.eu/badge/image/272787)
![achievement](https://www.hackthebox.eu/storage/achievements/ee137455c9f1e4b9d295380cc6483251.png)
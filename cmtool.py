#!/usr/bin/env python
import requests

logtypes = {
    'firewall': {
        'id': 2,
        'find': ['Description', 'Count', 'Last Occurrence', 'Target', 'Source']
    },
    'event': {
        'id': 1,
        'find': ['Time', 'Priority', 'ID', 'Text', 'Endpoint']
    },
    'system': {
        'id': 0,
        'find': ['Time', 'Priority', 'Description']
    }
}


def extract_logs(resp, find):
    """helper function for extracting log info"""

    from bs4 import BeautifulSoup as bs

    soup = bs(resp.text, 'lxml')
    tables = soup.find_all('td')
    seen = [None, None, None]
    found = [t.text.strip() for t in tables]

    x = 0

    while x < len(found) - 2 and find != found[x:x + len(find)]:
        x += 1

    x += len(find)

    while x < len(found):
        hive = dict(zip(find, found[x:x + len(find)]))
        yield(hive)
        x += len(find)


def get_logs(address, username, password, stdout=True):
    """gets the logs from the cable modem"""

    with requests.session() as s:

        payload = {'loginUsername': username, 'loginPassword': password}
        base_url = 'http://{0}'.format(address)
        r = s.get(base_url)
        login_url = base_url + '/goform/home_loggedout'
        s.post(login_url, data=payload)

        logs_url = base_url + '/troubleshooting_logs.asp'
        log_post_url = base_url + '/goform/troubleshooting_logs'

        for log_name, log_info in logtypes.items():
            s.get(logs_url)
            print('going to {0}'.format(log_name))

            r = s.post(log_post_url, data={
                'logtype': log_info['id'],
                'timeframe': 4,
            })

            for log in extract_logs(r, log_info['find']):

                log['_log_type'] = log_name

                if stdout:
                    print(log)

                yield(log)


def reboot(address, username, password):
    """reboots the cable modem"""

    with requests.session() as s:

        payload = {'loginUsername': username, 'loginPassword': password}
        base_url = 'http://{0}'.format(address)
        r = s.get(base_url)
        print('connecting')
        login_url = base_url + '/goform/home_loggedout'
        s.post(login_url, data=payload)

        print('rebooting')
        reset_url = base_url + '/goform/restore_reboot'
        payload = {'resetbt': 1}
        s.post(reset_url, data=payload)


if __name__ == '__main__':

    from argparse import ArgumentParser
    from pprint import pprint

    parser = ArgumentParser()
    parser.add_argument('action', choices=('logs', 'reboot'))
    parser.add_argument('--address', default='10.0.0.1')
    parser.add_argument('--username', default='admin')
    parser.add_argument('--password', default='password')

    args = parser.parse_args()

    info = {k: v for k, v in args.__dict__.items() if
            k in ['address', 'username', 'password']}

    print('executing action {0} on {1}'.format(args.action, info['address']))

    if args.action == 'logs':
        for log in get_logs(**info, stdout=True):
            print(log)

    elif args.action == 'reboot':
        reboot(**info)

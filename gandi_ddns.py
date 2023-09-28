#!/usr/bin/python3

import configparser as configparser
import sys
import os
import requests
import json
import ipaddress
from datetime import datetime
import time

config_file = "config.txt"

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_RETRIES = 3


PUBLIC_IP_SITES_LOADERS = {
    'https://api.ipify.org/?format=json': lambda resp: str(resp.json()['ip']),
    'http://ip.42.pl/raw': lambda resp: str(resp.text),
    'http://jsonip.com': lambda resp: str(resp.json()['ip']),
    'http://httpbin.org/ip': lambda resp: str(resp.json()['origin']).split(',')[0].strip(),
}


class GandiDdnsError(Exception):
    pass

def get_public_ip():
    for site, loader in PUBLIC_IP_SITES_LOADERS.items():
        print(f"getting public IP from {site}")
        resp = requests.get(site)
        if resp.status_code >= 400:
            print(f"site {site} returned {resp.status_code} trying next site...")
            continue
        public_ip = loader(resp)
        if not(ipaddress.IPv4Address(public_ip)):  # check if valid IPv4 address
            raise GandiDdnsError('Got invalid IP: ' + public_ip)
        return public_ip
    else:
        raise ValueError("unable to lookup public IP... check settings")

def get_ip(retries):
    # Get external IP with retries

    # Start at 5 seconds, double on every retry.
    retry_delay_time = 5
    for attempt in range(retries):
        try:
            return get_public_ip()
        except GandiDdnsError as e:
            print('Getting external IP failed: %s' % e)
            print('Waiting for %d seconds before trying again' % retry_delay_time)
            time.sleep(retry_delay_time)
            # Double retry time, cap at 60s.
            retry_delay_time = min(60, 2 * retry_delay_time)
        print('Exhausted retry attempts')
        sys.exit(2)


def read_config(config_path):
    # Read configuration file
    cfg = configparser.ConfigParser()
    cfg.read(config_path)

    return cfg


def get_record(url, headers):
    # Get existing record
    r = requests.get(url, headers=headers)

    return r


def update_record(url, headers, payload):
    # Add record
    r = requests.put(url, headers=headers, json=payload)
    if r.status_code != 201:
        print(('Record update failed with status code: %d' % r.status_code))
        print((r.text))
        sys.exit(2)
        print('Zone record updated.')

    return r


def main():
    path = config_file
    if not path.startswith('/'):
        path = os.path.join(SCRIPT_DIR, path)

    if (not os.path.exists(path)):
        sys.exit("Could not find 'config.txt' file.")
    config = read_config(path)
    if not config:
        sys.exit("Please fill in the 'config.txt' file.")

    for section in config.sections():
        print('%s - section %s' % (str(datetime.now()), section))

        # Retrieve API key
        apikey = config.get(section, 'apikey')

        # Set headers
        headers = {'Content-Type': 'application/json', 'Authorization': 'Apikey %s' % apikey}

        # Set URL
        url = '%sdomains/%s/records/%s/A' % (config.get(section, 'gandi_api'),
                                             config.get(section, 'domain'), config.get(section, 'a_name'))
        print(url)
        # Discover External IP
        retries = int(config.get(section, 'retries', fallback=DEFAULT_RETRIES))
        external_ip = get_ip(retries)
        print(('External IP is: %s' % external_ip))

        # Prepare record
        payload = {'rrset_ttl': config.get(section, 'ttl'), 'rrset_values': [external_ip]}

        # Check current record
        record = get_record(url, headers)

        if record.status_code == 200:
            print(('Current record value is: %s' % json.loads(record.text)['rrset_values'][0]))
            if(json.loads(record.text)['rrset_values'][0] == external_ip):
                print('No change in IP address. Goodbye.')
                continue
        else:
            print('No existing record. Adding...')

        update_record(url, headers, payload)


if __name__ == "__main__":
    main()

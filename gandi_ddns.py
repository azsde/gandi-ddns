#!/usr/bin/python3

import configparser as configparser
import sys
import os
import requests
import json
import ipaddress
import time
import logging

from requests.exceptions import ConnectionError

config_file = "config.txt"

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

# The time between checks of ip changes (in seconds)
DEFAULT_TIME_BETWEEN_CHECKS = 300

PUBLIC_IP_SITES_LOADERS = {
    'https://api.ipify.org/?format=json': lambda resp: str(resp.json()['ip']),
    'http://ip.42.pl/raw': lambda resp: str(resp.text),
    'http://jsonip.com': lambda resp: str(resp.json()['ip']),
    'http://httpbin.org/ip': lambda resp: str(resp.json()['origin']).split(',')[0].strip(),
}


class GandiDdnsError(Exception):
    pass

def get_public_ip():
    # Try every site
    for site, loader in PUBLIC_IP_SITES_LOADERS.items():
        logger.info(f"Getting public IP from {site}")
        resp = requests.get(site)
        # Try next site
        if resp.status_code >= 400:
            logger.warning(f"Site {site} returned {resp.status_code} trying next site...")
            continue
        # Parse IP
        public_ip = loader(resp)
        if not(ipaddress.IPv4Address(public_ip)):  # check if valid IPv4 address
            raise GandiDdnsError('Got invalid IP: ' + public_ip)
        return public_ip

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
    logger.info("Updating record ...")
    # Add record
    r = requests.put(url, headers=headers, json=payload)
    if r.status_code != 201:
        logger.error(('Record update failed with status code: %d' % r.status_code))
        logger.error((r.text))
    else:
        logger.info("Record succesfully updated.")


def main():
    logger.info("Starting gandi_ddns_updater ...")

    logger.info("Loading config.txt file ...")
    path = config_file
    if not path.startswith('/'):
        path = os.path.join(SCRIPT_DIR, path)

    if (not os.path.exists(path)):
        logger.error(f"Could not find {path} file.")
        sys.exit()
    config = read_config(path)
    if not config:
        logger.error(f"Invalid configuration file.")
        sys.exit("")

    # Retrieve config parameters
    section = "local"
    apikey = config.get(section, 'apikey')
    gandi_api = config.get(section, 'gandi_api')
    domain = config.get(section, 'domain')
    a_name = config.get(section, 'a_name')
    ttl = config.get(section, 'ttl')
    time_between_checks = int(config.get(section, 'time_between_checks', fallback=DEFAULT_TIME_BETWEEN_CHECKS))

    # Set headers
    headers = {'Content-Type': 'application/json', 'Authorization': 'Apikey %s' % apikey}

    # Set URL
    url = '%sdomains/%s/records/%s/A' % (gandi_api, domain, a_name)

    previous_ip = None

    while(True):
        # Get the current ip
        try:
            current_ip = get_public_ip()
            logger.info(f"Current IP is: {current_ip}")
        except (ConnectionError, GandiDdnsError) as e :
            logger.warning(f"Could not check IP, check your network connectivity, trying again in {time_between_checks} seconds.")
            time.sleep(time_between_checks)
            continue

        # If the current IP has changed
        if current_ip != previous_ip:
            logger.info(f"IP Address has changed from {previous_ip} to {current_ip}")
            previous_ip = current_ip

            # Prepare record
            payload = {'rrset_ttl': ttl, 'rrset_values': [current_ip]}

            logger.debug(url)

            # Check current record
            record = get_record(url, headers)

            if record.status_code == 200:
                logger.debug(('Current record value is: %s' % json.loads(record.text)['rrset_values'][0]))
                if(json.loads(record.text)['rrset_values'][0] == current_ip):
                    logger.info(f"DNS value is already set to {current_ip}, no need to update it.")
                else:
                    logger.info("Current record is out of date, updating ...")
                    update_record(url, headers, payload)
            else:
                logger.info('No existing record or record out of date. Adding...')
                update_record(url, headers, payload)

        else:
            logger.info(f"IP Address is still {previous_ip}, no change needed.")

        logger.info(f"Next check in {time_between_checks} seconds.")
        time.sleep(time_between_checks)

if __name__ == "__main__":
    main()

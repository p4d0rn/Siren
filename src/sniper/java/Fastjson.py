import logging
import os
import time

import requests

from lib.connection.HttpEntity import Request
from lib.help.dnslog import DNS_LOG
from lib.help.dump import vul
from lib.help.dump import Rank


def fastjson_check(url):
    dns_log = DNS_LOG()
    with open(os.path.abspath(__file__) + '/../scripts/fastjson', 'r') as file:
        for line in file:
            payload = line.strip() % dns_log.domain
            try:
                Request('POST', url, data=payload, json_flag=True).send()
                if record := dns_log.check_log():
                    logging.warning("[+] FastJson vulnerable")
                    logging.warning("[+] payload: " + payload)
                    logging.warning("[+] DNS log: " + str(record))
                    return [vul("FastJson", payload, "DNS log: " + str(record), Rank.CRITICAL)]
            except requests.exceptions.Timeout:
                logging.error("[-] Target Host Connection Failure")

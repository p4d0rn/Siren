import copy
import random
import string
import logging
import time
from urllib.parse import urljoin
from html import escape

from lib.connection.HttpEntity import Request
from lib.help.dump import dumper, vul, Rank
from lib.help.parser import pos_check
from lib.help.settings import XSS

TOP_RISK_GET_PARAMS = {"id", 'action', 'type', 'm', 'callback', 'cb'}


def add_param(params):
    for i in TOP_RISK_GET_PARAMS:
        params[i] = 1
    return params


def generate_random_string(length):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for _ in range(length))


def send_payload(method, url, params, param_name, payload, identifier, flag=None) -> bool:
    if not flag:
        flag = generate_random_string(5).lower()  # randomly choose a padding string
    payload = payload % flag
    params[param_name] = payload
    res = Request(method, url, data=params).send()
    locations = pos_check(flag, res.body)
    for loc in locations:
        if flag in loc['detail'][identifier]:
            logging.log(XSS, "[+] %s params '%s' appears to be XSS injectable: %s" % (method, param_name, payload))
            dumper().add_vul(vul(
                "XSS", escape(payload), "%s params '%s' appears to be XSS injectable" % (method, param_name), Rank.LOW
            ))
            return True
    return False


def xss_detect(method, url, params, param_k, param_v):
    target = params[param_k]
    # randomly select an element for value assignment
    params[param_k][random.randrange(len(target))] = param_v
    html = Request(method, url, data=params).send().body
    occurrences = pos_check(param_v, html)
    for o in occurrences:
        pos = o['pos']
        if pos == 'text' or pos == 'tag':
            # controllable javascript
            # if o['detail']['tag'] == 'script':
            #     script_check(method, url, params, param_k)
            # else:
            # tag in tag
            payload = "<%s/>"
            send_payload(method, url, params, param_k, payload, 'tag')
        if pos == 'key':
            # <div tar='xxx'></div>
            # <div ><flag x='xxx'></div>
            # check whether flag tag exists
            payload = "><%s x"
            send_payload(method, url, params, param_k, payload, 'tag')
        if pos == 'value':
            # <div id=tar class=xxx></div>
            # <div id= /><flag/><div class=xxx></div>
            # check whether flag tag exists
            parent_tag = o['detail']['tag']
            if parent_tag in ('href', 'src', 'action'):
                logging.log(XSS, '[+] suspicious controllable domain %s' % parent_tag)
            for closure in ('\'', '\"', ' '):
                payload = f"{closure}/><%s/><{parent_tag}"
                send_payload(method, url, params, param_k, payload, 'tag')
                payload = f"{closure} %s=prompt(1)"
                send_payload(method, url, params, param_k, payload, 'attributes', flag='onmouseover')
        if pos == 'comment':
            # <!-- Comments Here tar -->
            # <!-- Comments Here --><flag/><!-- -->
            payload = f"--><%s/><!--"
            send_payload(method, url, params, param_k, payload, 'tag')


def xss_check(url, link_params):
    params = copy.deepcopy(link_params)
    start = time.time()
    for item in params:
        _url = urljoin(url, item['link'])
        logging.info(_url)
        for k, v in item['qs'].items():
            xss_detect(item['method'], _url, item['qs'], k, 'xsscheck')
    duration = time.time() - start
    dumper().set_scan_time("xss", duration)
    logging.info(f"[-] XSS check consumes {duration} seconds")

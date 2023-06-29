import logging
import sys
from re import search, I

from lib.connection.HttpEntity import Request
from lib.help.dump import dumper
from lib.help.settings import FINGER
from requests.exceptions import ConnectionError

SERVER_LIB = (
    "nginx", "apache", "Werkzeug", "openresty", "gunicorn", "Tengine"
)
OS_LIB = (
    "Debian", "CentOS", "Ubuntu"
)


def check_program(headers):
    keys = headers.keys()
    if 'set-cookie' in keys:
        if search("JSESSIONID", headers["set-cookie"], I):
            return "java"
        if any(search(x, headers["set-cookie"], I) for x in ("PHPSESSID", "laravel")):
            return "php"
    if 'server' in keys:
        if search(r"php/?([\d.]+)?", headers["server"], I):
            return "php"
        if any(search(x, headers["server"], I) for x in ('Werkzeug', 'Python')):
            return "python"
    if 'x-powered-by' in keys:
        if search(r"php/?([\d.]+)?", headers["x-powered-by"], I):
            return "php"
        if search("Express", headers["x-powered-by"], I):
            return "node"
    return 'unknown'


def check_framework(headers):
    keys = headers.keys()
    if 'set-cookie' in keys:
        if search("laravel", headers["set-cookie"], I):
            return "laravel"
    if 'server' in keys:
        if search('werkzeug', headers["server"], I):
            return "flask"
        if search('wsgiserver', headers["server"], I):
            return "django"
    if 'x-powered-by' in keys:
        if search("express", headers["x-powered-by"], I):
            return "express"
    return 'unknown'


def check_os(headers):
    keys = headers.keys()
    if 'server' in keys:
        for x in OS_LIB:
            if search(x, headers["server"], I):
                return x
    if 'x-powered-by' in keys:
        for x in OS_LIB:
            if search(x, headers["x-powered-by"], I):
                return x
    return 'unknown'


def check_server(headers):
    keys = headers.keys()
    if 'server' in keys:
        for x in SERVER_LIB:
            if search(x, headers['server'], I):
                return x
        return headers['server']
    return 'unknown'


def get_finger(url) -> dict:
    try:
        r = Request('GET', url).send()
        infos = {}
        module = sys.modules[__name__]
        dirs = dir(module)
        functions = [(name[6:], getattr(module, name)) for name in dirs if name.startswith('check') and
                     callable(getattr(module, name))]
        for func in functions:
            infos[func[0]] = func[1](r.headers)
        return infos
    except ConnectionError as e:
        logging.error("Connection Failure To Target Host")
        quit()


def finger_check(url):
    fingers = get_finger(url)
    # determine just by path extension
    if 'php' in url:
        fingers['program'] = 'php'
    if 'jsp' in url:
        fingers['program'] = 'java'
    logging.info("[+] Fingerprint detected -> ")
    dumper().add_fp(fingers)
    for k, v in fingers.items():
        logging.log(FINGER, f"[*] {k} : {v}")

import copy
import difflib
import http.client
import logging
import time
from itertools import product
from multiprocessing import Pool, Manager
from urllib.parse import urljoin

from bs4 import BeautifulSoup
import random
import re

from lib.connection.HttpEntity import Request
from lib.help.dump import dumper, vul, Rank
from lib.help.settings import SQLI

LIKE_THRESHOLD = 0.99
ERROR_TEST = ('\'', '\')', '"', '")')
BOOLEAN_TEST = ("AND %d=%d", "OR NOT %d=%d")
PREFIXES = ("' ", '" ', "') ", '") ', " ", ") ")
SUFFIXES = (" ", "-- ", "#")
WAF_BYPASS = {
    '': [''],
    'blank': ['/**/', '()', '\t', '\n'],
    'and': ['&&'],
    'or': ['||']
}
DBMS_ERRORS = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (
        r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*",
        r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (
        r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
               r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}
RANDINT = random.randint(1, 10)
BLOCKED_IP_REGEX = r"(firewall|waf|block|ban).*?(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall|)"
BLOCKED_IP_PATTERN = re.compile(BLOCKED_IP_REGEX, re.I)
RET_REPLACE = r"(?i)[^>]*(AND|OR)[^<]*%d[^<]*" % RANDINT
RET_REPLACE_PATTERN = re.compile(RET_REPLACE)


def retrieve_res(url: str, method: str, payload: dict) -> dict:
    record = {
        "code": http.client.OK
    }
    try:
        if method == "POST":
            res = Request(method, url, data=payload).send()
        else:
            res = Request(method, url, data=payload).send()
        record["html"] = "" if BLOCKED_IP_PATTERN.search(res.body) else res.body
    except Exception as e:
        logging.error(e)
        record["code"] = 0
        record.update({"html": ""})
    record["html"] = RET_REPLACE_PATTERN.sub("__REFLECT__", record["html"])
    soup = BeautifulSoup(record["html"], 'html.parser')
    if title := soup.title:
        record["title"] = title
    else:
        record["title"] = ""
    record.update({"text": soup.get_text()})
    return record


def bool_detect(template, params, url, method, bool_vul):
    if not bool_vul.value:
        for key, value in params.items():
            for index in range(len(value)):
                before = retrieve_res(url, method, params)
                payloads = dict()
                for x in (True, False):
                    payloads[x] = copy.deepcopy(params)
                    payloads[x][key][index] += template % (RANDINT, RANDINT if x else RANDINT + 1)
                afters = dict((x, retrieve_res(url, method, payloads[x])) for x in (True, False))
                if all(record['code'] and record['code'] < 500 for record in
                       (before, afters[True], afters[False])):
                    if any(before[x] == afters[True][x] and before[x] != afters[False][x] for x in
                           ('code', 'title')):
                        bool_vul.value = True
                    else:
                        ratios = difflib.SequenceMatcher(None, afters[True]['html'],
                                                         afters[False]['html']).ratio()
                        if ratios < LIKE_THRESHOLD:
                            bool_vul.value = True
                if bool_vul.value:
                    print(SQLI, "[SQLI] [+] %s parameter '%s' appears to be Boolean SQLi vulnerable: %s" % (
                        method, key, payloads[True][key][index]))
                    return vul(
                        "SQLI", payloads[True][key][index],
                        "%s params '%s' appears to be Boolean SQLi vulnerable" % (method, key), Rank.MEDIUM
                    )


def sqli_detect(url: str, method: str, params: dict, process: int):
    error_vul = False
    error_start = time.time()
    for key, value in params.items():
        logging.info("[+] scanning %s parameter '%s' " % (method, key))
        for index in range(len(value)):
            before = retrieve_res(url, method, params)
            # Error SQLi Check
            for closure in ERROR_TEST:
                if not error_vul:
                    payload_cp = copy.deepcopy(params)
                    payload_cp[key][index] += closure
                    after = retrieve_res(url, method, payload_cp)
                    for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                        if re.search(regex, after["html"], re.I) and not re.search(regex, before["html"], re.I):
                            logging.log(SQLI, " * %s parameter '%s' appears to be %s error SQLi vulnerable: %s" % (
                                method, key, dbms, payload_cp[key][index]))
                            dumper().add_vul(vul(
                                "SQLI", payload_cp[key][index],
                                "%s params '%s' appears to be %s error SQLi vulnerable" % (method, key, dbms),
                                Rank.MEDIUM
                            ))
                            error_vul = True
    error_sqli_duration = time.time() - error_start
    logging.info(f"error based SQLI detection consumes {error_sqli_duration} seconds")
    dumper().set_scan_time("error_sqli", error_sqli_duration)
    # Boolean SQLi Check
    manager = Manager()
    bool_vul = manager.Value('b', False)
    templates = []
    for prefix, condition, suffix in product(PREFIXES, BOOLEAN_TEST, SUFFIXES):
        for k, v in WAF_BYPASS.items():
            for item in v:
                template = ("%s%s%s" % (prefix, condition, suffix)).replace(k, item)
                templates.append(template)
    bool_start = time.time()
    with Pool(processes=process) as pool:
        results = pool.starmap(bool_detect, [(temp, params, url, method, bool_vul) for temp in templates])
        results = list(filter(lambda x: x is not None, results))
        for result in results:
            dumper().add_vul(result)
    blind_sqli_duration = time.time() - bool_start
    logging.info(f"bool based SQLI detection consumes {blind_sqli_duration} seconds")
    dumper().set_scan_time("blind_sqli", blind_sqli_duration)


def sqli_check(url, link_params, process):
    start = time.time()
    for item in link_params:
        _url = urljoin(url, item['link'])
        logging.info(_url)
        sqli_detect(_url, item['method'], item['qs'], process)
    logging.info(f"[-] SQLI check consumes totally {time.time() - start} seconds")

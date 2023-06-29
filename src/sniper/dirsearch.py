import logging
import time
from multiprocessing import Pool
from urllib.parse import urljoin
from lib.connection.HttpEntity import Request
from lib.help.dump import dumper
from lib.help.settings import get_search_list
from retrying import retry
from tqdm import tqdm
from socket import socket
from lib.connection.rate import hooked_connect

socket.connect = hooked_connect

BASE_URL = 'DUMMY'
PATHS = []


def read_dic(root: str, path: str):
    with open(root + path) as f:
        targets = f.readlines()
        for target in targets:
            PATHS.append((BASE_URL, target.strip()))


@retry(wait_fixed=1000, stop_max_attempt_number=3)
def probe(path):
    try:
        res = Request("GET", urljoin(path[0], path[1])).send()
        if res.is_ok:
            # return None by default
            return {"code": res.status, "path": path[1]}
    except Exception as e:
        pass


def search(url, process, program):
    global BASE_URL
    BASE_URL = url
    search_tuples = [(key, value) for key, values in get_search_list(program).items() for value in values]
    for arg in search_tuples:
        read_dic(*arg)  # 读取字典文件
    start = time.time()
    results = []
    with Pool(processes=process) as pool:  # 开启多线程池
        for result in tqdm(pool.imap_unordered(probe, PATHS), total=len(PATHS), colour='CYAN', position=0):
            if result:
                tqdm.write(f"\033[36m[+] potential path found: {result['code']} - {result['path']}\033[0m")
                results.append(result)
    results = list(filter(lambda x: x is not None, results))  # 获取扫描结果,存活的路径
    return results, time.time() - start  # 计算扫描时间


def dirsearch(url, num, program):
    dirs, search_time = search(url, num, program)
    dirs = [{"code": 200, "path": "index.php"}, {"code": 200, "path": "index.html"}]
    dumper().path = dirs
    dumper().set_scan_time("path", search_time)
    logging.info("Directory Search consumes %d seconds" % search_time)

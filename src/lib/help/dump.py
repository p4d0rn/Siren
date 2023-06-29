import time
from enum import Enum

from jinja2 import Environment, FileSystemLoader

# 创建模板引擎
env = Environment(loader=FileSystemLoader('./'))


class Rank(Enum):
    CRITICAL = 'Critical'
    MEDIUM = 'Medium'
    LOW = 'Low'


class vul:
    vul_type = ""
    payload = ""
    info = ""
    rank = None
    scan_time = ""

    def __init__(self, vul_type, payload, info, rank):
        self.vul_type = vul_type
        self.payload = payload
        self.info = info
        self.rank = rank.value


def singleton(cls, *args, **kwargs):
    instances = {}

    def _singleton():
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return _singleton


@singleton
class dumper:
    def __init__(self):
        self.vuls = []
        self.target = ""
        self.path = []
        self.scan_time = {
            "path": None,
            "xss": None,
            "blind_sqli": None,
            "error_sqli": None,
            "custom": None
        }
        self.total_time = None
        self.finger_print = []
        self.vuls_counter = {"low_counter": 0, "mid_counter": 0, "critical_counter": 0}
        self.type_flag = {"xss": False, "sqli": False, "other": False}

    def add_vul(self, _vul):
        self.vuls.append(_vul)

    def set_scan_time(self, k, v):
        self.scan_time[k] = '{:.1f}'.format(v)

    def add_target(self, target):
        self.target = target

    def add_fp(self, fp):
        self.finger_print.append(fp)

    def set_recommendation(self):
        for vul in self.vuls:
            if vul.vul_type == "XSS":
                self.type_flag['xss'] = True
            elif vul.vul_type == "SQLI":
                self.type_flag['sqli'] = True
            else:
                self.type_flag['other'] = True

    def count_vuls(self):
        for v in self.vuls:
            if v.vul_type == "XSS":
                self.vuls_counter["low_counter"] += 1
            elif v.vul_type == "SQLI":
                self.vuls_counter["mid_counter"] += 1
            else:
                self.vuls_counter["critical_counter"] += 1

    def out(self):
        # 渲染模板
        env.globals['vuls'] = self.vuls
        env.globals['target'] = self.target
        env.globals['finger_print'] = self.finger_print
        env.globals['path'] = self.path

        env.globals['scan_time'] = self.scan_time
        env.globals['total_time'] = self.total_time
        self.count_vuls()
        self.set_recommendation()
        env.globals['vuls_counter'] = self.vuls_counter
        env.globals['type_flag'] = self.type_flag

        template = env.get_template('./lib/help/template.html')
        result = template.render()
        now = int(round(time.time() * 1000))
        ts = time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime(now / 1000))
        with open(f'./output/report_{ts}.html', 'wb') as f:
            f.write(result.encode("utf-8"))

# dumper().add_vul(vul("xss", "11", "111", Rank.CRITICAL))
# dumper().add_vul(vul("sqli", "11", "111", Rank.MEDIUM))
# dumper().add_vul(vul("xss", "11", "111", Rank.CRITICAL))
# dumper().add_vul(vul("sqli", "11", "111", Rank.LOW))
#
# dumper().add_path({"code": "200", "path": "222"})
# dumper().add_path({"code": "210", "path": "222"})
# dumper().add_path({"code": "220", "path": "222"})
# dumper().add_path({"code": "230", "path": "222"})
#
# dumper().add_fp({"os": "Likx", "framework": "33333", "program": "dfasdf", "server": "333"})
#
# dumper().add_scantime({"path": 444})
# dumper().add_scantime({"xss": 4444})
# dumper().add_scantime({"blind_sqli": 44444})
#
# dumper().add_target("444")
#
# dumper().out()

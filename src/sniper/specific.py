import time

from lib.help.dump import dumper
from sniper.crawl import get_params
from sniper.java.Solr import Solr
from sniper.java.Struts2 import Struts2
from sniper.java.Fastjson import fastjson_check
from sniper.java.Flink import Flink
from sniper.php.ThinkPHP import ThinkPHP


def specified_poc(poc, url):
    result = None
    start = time.time()
    if poc == 'Fastjson':
        result = fastjson_check(url)
    if poc == 'Flink':
        result = Flink().flink_check(url)
    if poc == 'Solr':
        result = Solr(url).solr_check()
    if poc == 'ThinkPHP':
        result = ThinkPHP(url).think_check()
    if poc == 'Struts2':
        link_params = get_params(url)
        result = Struts2().s2_check(url, link_params)
    dumper().set_scan_time("custom", time.time() - start)
    if result:
        for res in result:
            if res:
                dumper().add_vul(res)

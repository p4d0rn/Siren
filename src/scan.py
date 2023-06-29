import time

import click
import logging

from sniper.fingerprint import finger_check
from lib.help.settings import init, LOGO, CVES, validate_num, VULS
import lib.help.settings
from lib.help.dump import dumper
from sniper.crawl import get_params
from sniper.dirsearch import dirsearch
from sniper.specific import specified_poc
from sniper.sqli import sqli_check
from sniper.xss import xss_check


@click.command()
@click.option('-u', "--url", help="url to scan")
@click.option('-n', "--num", type=int, default=1, callback=validate_num, help="process number in scanning",
              show_default=True)
@click.option('-p', '--program', type=click.Choice(['all', 'php', 'java']), show_default=True,
              help="specify the backend program language when searching directories")
@click.option('-c', '--custom', type=click.Choice(VULS), help="Customization Mode Else Traditional Mode")
@click.option('--dir-brute', is_flag=True, help="discover potential web path")
@click.option('--risk', default='5', type=click.Choice([str(x) for x in range(11)]), show_default=True,
              help="The higher risk, the faster dirsearch work")
@click.option('-l', '--show', is_flag=True, help="list all the vuls supported")
def main(url, num, program, custom, dir_brute, risk, show):
    """A tiny little scanner for vul detection"""
    start = time.time()
    logger = logging.getLogger()
    init()
    if show:
        for cve in CVES:
            print(f"\033[32m{'[+] ' + cve}\033[0m")
        return
    print(f"\033[32m{LOGO}\033[0m")
    lib.help.settings.RATE = int(risk)
    logger.info("Start to scan target: " + url)
    dumper().add_target(url)
    if custom:
        specified_poc(custom, url)
    else:
        finger_check(url)
        if dir_brute:
            dirsearch(url, num, program)
        link_params = get_params(url)
        logger.info("[+] Start to test XSS")
        xss_check(url, link_params)
        logger.info("[+] Start to test SQLI")
        sqli_check(url, link_params, num)
    dumper().total_time = '{:.1f}'.format(time.time() - start)
    dumper().out()


if __name__ == '__main__':
    main()

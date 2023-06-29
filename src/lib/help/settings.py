import logging

import click
import colorlog
from tqdm import tqdm
from multiprocessing import cpu_count

LOGO = r"""
       _                   
  ___ (_) _ __   __    ___  
/',__)| |( '__)/'__`\/' _ `\
\__, \| || |  (  ___/| ( ) |
(____/(_)(_)  `\____)(_) (_)
    """

COMMON = "./armor/common/"
JAVA = "./armor/java/"
PHP = "./armor/php/"
OTHER = "./armor/others"
SEARCH_LIST = {
    COMMON: ['log', 'source', 'ssh', 'traversal'],
    JAVA: ['jsp', 'java_web', 'spring', 'swagger', 'tomcat'],
    PHP: ['php']
}
RATE = 1
SQLI = 23
XSS = 22
FINGER = 21
VULS = [
    'Fastjson',
    'Flink',
    'Solr',
    'Struts2',
    'ThinkPHP'
]
CVES = [
    'XSS',
    'SQLI',
    'FastJson',
    'Struts2 S2-001',
    'Struts2 S2-005',
    'Struts2 S2-007',
    'Struts2 S2-008',
    'Struts2 S2-013',
    'Struts2 S2-015',
    'Struts2 S2-016',
    'Struts2 S2-032',
    'Struts2 S2-045',
    'Struts2 S2-046',
    'Struts2 S2-053',
    'Struts2 S2-057',
    'Struts2 S2-061',
    'Apache Solr RCE CVE-2017-12629',
    'Apache Solr XXE CVE-2017-12629',
    'Apache Solr RCE CVE-2019-17558',
    'Apache Solr RemoteStreaming Arbitrary File Reading and SSRF',
    'Apache Flink Path Traversal CVE-2020-17519',
    'ThinkPHP 2.x RCE',
    'Thinkphp5 5.0.22/5.1.29 RCE',
    'ThinkPHP5 5.0.23 RCE',
    'Thinkphp6 Lang LFI'
]


def get_search_list(p):
    if p == 'all':
        return SEARCH_LIST
    if p == 'java':
        return {key: value for key, value in SEARCH_LIST.items() if key != PHP}
    if p == 'php':
        return {key: value for key, value in SEARCH_LIST.items() if key != JAVA}
    else:
        return {COMMON: SEARCH_LIST[COMMON]}


class TqdmLoggingHandler(logging.Handler):
    # make logging compatible to tqdm
    # logging does not interrupt the progress bar
    def __init__(self, level=logging.NOTSET):
        super(TqdmLoggingHandler, self).__init__(level)

    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg)
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)


def init():
    logging.addLevelName(XSS, "XSS")
    logging.addLevelName(SQLI, "SQLI")
    logging.addLevelName(FINGER, "FINGER")

    # Create a logger object
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Create a color formatter for the console handler
    console_formatter = colorlog.ColoredFormatter(
        fmt='%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S',
        log_colors={
            'FINGER': 'blue',
            'XSS': 'purple',
            'SQLI': 'yellow',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )

    # Create a console handler and set its formatter
    # console_handler = TqdmLoggingHandler()
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)

    # Add the console handler to the logger
    logger.addHandler(console_handler)


def validate_num(ctx, param, value):
    if value > cpu_count():
        raise click.BadParameter('process num exceeds the core num of your computer')
    return value

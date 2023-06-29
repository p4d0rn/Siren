from sniper.xss import xss_detect

DUMMY_URL = "https://xssaq.com/yx/level.php"
xss_detect('GET', DUMMY_URL, {'keyword': 'xsscheck'}, 'keyword', 'xsscheck')

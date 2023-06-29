from lib.help.settings import init
from sniper.sqli import sqli_detect

if __name__ == '__main__':
    # 测试前请确保靶场已初始化，即连接数据库
    init()
    url = "http://sqli.exp-9.com/Less-1/"
    sqli_detect(url, "GET", {"id": ["1"]})

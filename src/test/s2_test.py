from sniper.crawl import get_params
from sniper.java.Struts2 import Struts2

s2 = Struts2()
URL = "http://xxx/index.action"
link_params = get_params(URL)
print(link_params)
s2.s2_check(URL, link_params)

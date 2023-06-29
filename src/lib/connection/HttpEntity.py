from urllib.parse import urlparse
import urllib3
import requests
import json

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
# urllib3.disable_warnings()


class URL:
    def __init__(self, url: str, encoding="utf-8"):
        pattern = urlparse(url)
        self.url = url
        self.scheme = pattern.scheme
        self.port = 80 if pattern.port is None else pattern.port  # 默认80端口
        self.hostname = pattern.hostname
        self.netloc = pattern.netloc
        self.path = pattern.path
        self.params = pattern.params  # 输入参数 /path;q=zzz
        self.query = pattern.query  # 查询参数 ?a=xxx&b=yyy
        self.static_ext = ['png', 'jpg', 'gif', 'bmp', 'svg', 'pdf', 'ico',
                           'svg', 'tff', 'woff', 'woff2',
                           'css', 'sass', 'scss', 'less', 'js']

    @property
    def is_static(self) -> bool:
        dot = self.path.rfind('.') + 1
        if dot > 0:  # 存在后缀名
            if self.path[dot:] in self.static_ext:
                return True
        return False


class Response:
    def __init__(self, response: requests.models.Response):
        self.res = response
        self.status = response.status_code
        self.headers = response.headers
        self.base_url = response.url
        self.body = response.content.decode('utf-8')
        self.redirect_urls = set()
        self.body_urls = set()

    @property
    def is_ok(self):
        return True if self.status != 404 else False

    def get_redirect(self):
        if self.status in (301, 302):
            if redirect := self.headers.get('Location'):
                self.redirect_urls.add(redirect)


class Request:
    def __init__(self, method, url, headers=None, data=None, json_flag=False, timeout=None):
        self.headers = {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": 'xxx'
        }
        self.timeout = timeout
        self.params = None
        self.data = None
        if method == 'GET':
            self.params = data
        elif json_flag:
            self.headers.update({"Content-Type": "application/json"})
            if type(data) == dict:
                self.data = json.dumps(data, separators=(',', ':'))
            if type(data) == str:
                self.data = data
        else:
            self.data = data
        if headers:
            self.headers.update(headers)
        self.method = method
        self.url = url

    def send(self):
        res = requests.request(
            method=self.method,
            url=self.url,
            headers=self.headers,
            params=self.params,
            data=self.data,
            # proxies={'http': '127.0.0.1:8080'},
            # verify=False,
            allow_redirects=False,
            timeout=self.timeout
        )
        return Response(res)

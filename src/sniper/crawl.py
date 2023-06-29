import logging
import time
import socket
from selenium import webdriver
from selenium.webdriver import DesiredCapabilities
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup
from urllib.parse import parse_qs, urlparse

from lib.connection.dns import get_cached_addr
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

socket.getaddrinfo = get_cached_addr

URLS = set()  # deduplicate
HOST = ''  # check the same host
PAGES = []
link_with_params = set()


def recursive_get_content(driver, links: list):
    for link in links:
        driver.get(link)
        time.sleep(1)
        PAGES.append(driver.page_source.encode('utf-8'))
        URLS.add(link)
    _lists = []
    for a in driver.find_elements(By.TAG_NAME, 'a'):
        href = a.get_attribute('href')
        if href is not None:
            href = href.strip()
            if href.startswith("http") or href.startswith("https"):
                if urlparse(href).hostname == HOST:
                    if href not in URLS:
                        _lists.append(href)
    if _lists:
        recursive_get_content(driver, _lists)


def parse(content: str) -> list:
    link_dict = []
    soup = BeautifulSoup(content, 'html.parser')
    # get all hrefs attribute of `a` tag
    links = soup.find_all('a', href=True)
    for link in links:
        href = link['href']
        if urlparse(href).hostname == HOST:
            if href and href not in link_with_params:
                link_with_params.add(href)
                # append only when params exists
                if qs := parse_qs(urlparse(href).query):
                    link_dict.append({
                        'link': href,
                        'method': 'GET',
                        'qs': qs
                    })
    # get all forms
    forms = soup.find_all('form')
    for form in forms:
        method = str(form.get('method', 'GET')).upper()
        if method in ('GET', 'POST'):
            if action := form.get('action', ''):
                if action not in link_with_params:
                    link_with_params.add(action)
                    params = {}
                    for input_tag in form.find_all('input'):
                        # skip submit type
                        if input_tag.get('type') == 'submit':
                            continue
                        # get param name and its default value
                        if name := input_tag.get('name'):
                            v_list = params.get(name, [])
                            v_list.append(input_tag.get('value', '1'))
                            params[name] = v_list
                    # `textarea` tag taken into account
                    for text_tag in form.find_all('textarea'):
                        if name := text_tag.get('name'):
                            v_list = params.get(name, [])
                            v_list.append(text_tag.get('value', '1'))
                            params[name] = v_list
                    # append only when params exists
                    if params:
                        link_dict.append({
                            'link': action,
                            'method': method,
                            'qs': params
                        })
    return link_dict


def get_params(url) -> list:
    initials = [url]
    global HOST
    HOST = urlparse(url).hostname

    driver_path = ChromeDriverManager(url="https://npm.taobao.org/mirrors/chromedriver",
                                      latest_release_url="https://npm.taobao.org/mirrors/chromedriver/LATEST_RELEASE",
                                      path=r"./Drivers").install()
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    # 防反爬对Selenium的检验
    options.add_experimental_option('excludeSwitches', ['enable-automation'])
    options.add_argument("--disable-blink-features")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument(
        'user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 '
        'Safari/537.36')
    # options.add_argument('--proxy-server=http://127.0.0.1:8080')
    driver = webdriver.Chrome(service=Service(driver_path), options=options)
    # driver = webdriver.Remote(
    #     command_executor="http://chrome:4444/wd/hub",
    #     desired_capabilities=DesiredCapabilities.CHROME,
    #     options=options
    # )
    logging.info("[+] Start to Crawl Pages")
    recursive_get_content(driver, initials)
    driver.quit()  # quit web driver
    results = []
    for page in PAGES:
        _dict = parse(str(page))
        if _dict:
            results.extend(_dict)
    return results

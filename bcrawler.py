import asyncio
from aiohttp import ClientSession
import mysql.connector
import logging
from ntpath import join
from typing_extensions import Self
from urllib.parse import urljoin
from numpy import empty
from urllib.parse import urlparse, urlunparse
from urllib.parse import urlencode
from urllib.parse import parse_qs
from urllib.parse import quote
import requests
from bs4 import BeautifulSoup
import sys
sys.tracebacklimit=0
from torch import argsort
from traitlets import Undefined
import argparse
import socket
from Wappalyzer import Wappalyzer, WebPage
from playwright.sync_api import sync_playwright, TimeoutError
import time
import urllib.parse
from playwright.async_api import async_playwright, TimeoutError
import base64
import binascii
import utils
import html
import subprocess
import json
from runVectors import SQL_Query

parser = argparse.ArgumentParser()
jobtoken = "test"

level = logging.DEBUG
fmt= '[%(levelname)s] %(asctime)s - %(message)s'
logging.basicConfig(filename='spam.log', level=level, format=fmt)

dbuser='root'
dbpassword='123456'
dbhost='127.0.0.1'
dbdatabase='mantis'

base_url = ''

SECURITY_HEADERS = {
    'x-frame-options': True,
    'strict-transport-security': True,
    'content-security-policy': True,
    'x-content-type-options': True,
    'referrer-policy': True,
    'permissions-policy': True,
    'server': False,
    'x-powered-by': False,
    'x-xss-protection': False
}

def run_script(url, token):
    print(f"[] Running script for URL: {url}, Token: {token}")
    subprocess.Popen(['py', 'runVectors.py', '-t', token])

def safe_urljoin(base, path):
    if path.startswith(('http://', 'https://')):
        return path

    parsed_base = urlparse(base)
    if path.startswith('/'):
        joined_path = path
    else:
        base_dir = parsed_base.path.rsplit('/', 1)[0]
        joined_path = base_dir + '/' + path

    final_url = urlunparse((
        parsed_base.scheme,
        parsed_base.netloc,
        joined_path,
        '', '', ''
    ))

    return final_url
    
async def analyze_dynamic(address):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        reload_detected = False

        def on_framenavigated(frame):
            nonlocal reload_detected
            print(f"[Event] Frame navigated to: {frame.url}")
            reload_detected = True

        page.on("framenavigated", on_framenavigated)
        page.on("console", lambda msg: print(f"[Console] {msg.text}"))

        await page.goto(address, wait_until="domcontentloaded")

        await page.evaluate("""
            (() => {
                const originalReload = location.reload;
                location.reload = function() {
                    console.log('[JS] location.reload() called');
                    originalReload.call(location);
                };
            })()
        """)

        print("[+] Page loaded, waiting for reloads...")

        last_title = None

        async def get_title_safe():
            try:
                return await page.title()
            except Exception:
                return None

        for _ in range(5):
            last_title = await get_title_safe()
            if last_title:
                break
            await asyncio.sleep(1)

        print(f"[+] Initial page title: {last_title}")

        timeout = time.time() + 30
        html = await page.content()
        while time.time() < timeout:
            await asyncio.sleep(1)
            title = await get_title_safe()
            if title and (reload_detected or title != last_title):
                print(f"[+] Detected reload/navigation: Title changed from '{last_title}' to '{title}'")
                reload_detected = False
                last_title = title

                try:
                    await page.wait_for_load_state("load", timeout=10000)
                    html = await page.content()
                    print(f"[+] New DOM length: {len(html)}")
                except TimeoutError:
                    print("[!] Timeout waiting for page to load")

        cookies = await context.cookies()
        cookie_dict = {cookie['name']: cookie['value'] for cookie in cookies}
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookie_dict.items())
        current_url = page.url

        await browser.close()
        return current_url, cookie_header, html
   
def SQL_Insert_Query(query , val):
        global dbhost, dbuser, dbpassword, dbdatabase
        cnx = mysql.connector.connect(host=dbhost,user=dbuser, password=dbpassword, database=dbdatabase)
        cursor = cnx.cursor()
        cursor.execute(query,val)
        cnx.commit()
        cursor.close()
        cnx.close()

def parse_query_string_to_dict(query_data):
    if isinstance(query_data, dict):
        return dict(query_data)
    elif isinstance(query_data, str):
        query_string = query_data.strip('&')
        if not query_string:
            return {}

        pairs = query_string.split('&')
        params = {}

        for pair in pairs:
            if not pair:
                continue
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key] = value
            else:
                params[pair] = ''

        return params

    else:
        raise TypeError("error.")

def detect_and_decode(s):
    decoded_versions = {}
    original = s

    # HTML Decode
    html_decoded = html.unescape(s)
    if html_decoded != s:
        decoded_versions['html'] = html_decoded
        s = html_decoded

    # URL Decode
    url_decoded = urllib.parse.unquote_plus(s)
    if url_decoded != s:
        decoded_versions['url'] = url_decoded
        s = url_decoded

    # Base64 Decode
    try:
        base64_decoded = base64.b64decode(s).decode('utf-8')
        decoded_versions['base64'] = base64_decoded
        s = base64_decoded
    except Exception:
        pass

    # Hex Decode
    try:
        hex_decoded = bytes.fromhex(s).decode('utf-8')
        decoded_versions['hex'] = hex_decoded
        s = hex_decoded
    except Exception:
        pass
    if not decoded_versions:
        #print("Dont Recognize")
        return original, 'PLAIN'
    #print("Decoded params")
    encodeType = 'PLAIN'
    for k, v in decoded_versions.items():
        #print(f"[{k.upper()}] → {v}")
        encodeType = k.upper()

    return s, encodeType

def update_input_value(inputs_string, key_to_update, new_value):
    params = {}
    pairs = inputs_string.strip('&').split('&')
    for pair in pairs:
        if '=' in pair:
            key, value = pair.split('=', 1)
            params[key] = value
        else:
            params[pair] = ''
    params[key_to_update] = new_value
    updated_inputs = urlencode(params, doseq=True)
    return updated_inputs

def analyze_security_headers(response_headers):
    global SECURITY_HEADERS
    results = {}
    headers = {k.lower(): v for k, v in response_headers.items()}

    for header, recommended in SECURITY_HEADERS.items():
        if header in headers:
            results[header] = {
                'present': True,
                'value': headers[header],
                'recommended': recommended
            }
        else:
            results[header] = {
                'present': False,
                'value': None,
                'recommended': recommended
            }

    return results

def check_http_https_support(domain):
    result = {
        'http_supported': False,
        'https_supported': False,
        'http_redirects_to_https': False,
        'vulnerable_tls_versions': []
    }
    
    VULNERABLE_TLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2']

    http_url = f'http://{domain}'
    https_url = f'https://{domain}'

    try:
        #print('1')
        http_response = requests.get(http_url, timeout=5, allow_redirects=False)
        result['http_supported'] = True
        location = http_response.headers.get('Location', '')
        if location and location.startswith('https://'):
            result['http_redirects_to_https'] = True
    except Exception as e:
        print('11')

    try:
        #print('2')
        https_response = requests.get(https_url, timeout=5)
        result['https_supported'] = True
    except Exception as e:
        print('22')

    # بررسی نسخه TLS
    #try:
    #    print('[1] Creating SSL context...')
    #    context = ssl.create_default_context()
    #
    #    print('[2] Wrapping socket...')
    #    conn = context.wrap_socket(
    #        socket.socket(socket.AF_INET),
    #        server_hostname=domain,
    #    )
    #
    #    print('[3] Setting timeout...')
    #    conn.settimeout(5)
    #
    #    print('[4] Connecting to server...')
    #    conn.connect((domain, 443))
    #
    #    print('[5] Getting TLS version...')
    #    tls_version = conn.version()
    #    print(f'[6] TLS version = {tls_version}')
    #
    #    result = {
    #        'tls_version': tls_version,
    #        'vulnerable': tls_version in VULNERABLE_TLS if tls_version else False
    #    }
    #except ssl.SSLError as e:
    #    result['vulnerable_tls_versions'].append(str(e))
    #except Exception as e:
    #    print('33')
    #print(result)
    return result

class Crawler:
    def __init__(self, urls=[]):
        self.visited_urls = set()
        self.form_actions = []
        self.form_log_list = []
        self.urls_to_visit = urls
        self.new_headers = ""
        self.requestCount = 0

    def get_url(self, url):
        global jobtoken
        try:
            headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0' , 'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8','cookie' : self.new_headers}
            response = requests.get(url,headers=headers)
            if isinstance(response, str):
                print("❌ Request error:", response)
                return
            if self.requestCount < 5:
                result = analyze_security_headers(response.headers)
                #print(result)
                self.requestCount = self.requestCount + 1
            elif self.requestCount == 5:
                self.requestCount = self.requestCount + 1
                result = analyze_security_headers(response.headers)
                #print(result)
                parsed_url = urlparse(url)
                hostname = parsed_url.hostname
                report = check_http_https_support(hostname)
                #print("222222222222222222")
                #print(report)
                base_query = "INSERT INTO securityheaders_tbl(sitebaseurl,headermissing,usertoken,httpsanylyze) VALUES (%s,%s,%s,%s)"
                values = (url,json.dumps(result),jobtoken,json.dumps(report));
                SQL_Insert_Query(base_query,values)
            return response.text
        except:
            #print("Error 4")
            pass
        
    def append_url_to_visit(self, url):
        if url not in self.visited_urls and url not in self.urls_to_visit:
            self.urls_to_visit.append(url)
    
    async def hello(self, url):
        try:
            
            url, headers2, html = await analyze_dynamic(url)
            print("[Result] Final URL:", url)
            if html and len(html) > 100:
                return html
            #print("[Result] Cookies (as headers):", headers2)
            self.new_headers = headers2
            headers = {
                'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0',
                'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'cookie': headers2
            }
            
            async with ClientSession(headers=headers) as session:
                async with session.get(url) as response:
                    text = await response.text(encoding='utf-8')
                    #print(text)
                    return text.encode('utf-8')
        except Exception as e:
            print(e)

    def extract_get_values(self, url):
        global jobtoken
        base_query = "INSERT INTO crawlprofile_tbl(usertoken,url,methodtype,inputtype,inputs,encodedinputs) VALUES (%s,%s,%s,%s,%s,%s)"
        if(len(url.split('?')) > 1):
            params = parse_query_string_to_dict(url.split('?')[1])
            testInput = url.split('?')[1]
            encodeType = 'PLAIN'
            if params:
                for k, v in params.items():
                    if v:
                        x,t = detect_and_decode(v)
                        if t:
                            encodeType = t
                            testInput = update_input_value(testInput, k, x)
            values = (jobtoken,url.split('?')[0],"GET",encodeType,url.split('?')[1],testInput)
            SQL_Insert_Query(base_query,values)
            
            if "pass" in url.split('?')[1].lower():
                base_query = "INSERT INTO findlogin_tbl(usertoken,url,methodtype,inputtype,inputs,status,iscaptcha) VALUES (%s,%s,%s,%s,%s,%s,%s)"
                values = (jobtoken,url,"GET",'Plain',url.split('?')[1],200,False) # todo find out captcha enabaled
                SQL_Insert_Query(base_query,values)
        else:
            values = (jobtoken,url,'GET','Plain','','')
            SQL_Insert_Query(base_query,values)
       
    def check_duplicate_forms(self, form):
        if form and form not in self.form_log_list and form["action"] not in self.form_actions:
            self.form_log_list.append(form)
            self.form_actions.append(form["action"])
        
    def get_form_details(self, form):
        global base_url
        try:
            details = {}
            action = form.attrs.get("action")
            method = form.attrs.get("method", "get")
            inputs = []
            for input_tag in form.find_all("input"):
                input_type = input_tag.attrs.get("type", "text")
                input_name = input_tag.attrs.get("name")
                input_value =input_tag.attrs.get("value", "")
                inputs.append({"type": input_type, "name": input_name, "value": input_value})
            if action and (not action.startswith('http')):
                action = urljoin(base_url, action)
            details["action"] = action
            details["method"] = method
            post_param = ''
            for values in inputs:
                post_param = values['name'] + '=' + quote(values['value']) + '&' + post_param
            details["inputs"] = post_param
            return details
        except:
            #print("Error 3")
            pass
        
    def crawl(self, url, state):
        global jobtoken, base_url
        try:
            html = "test"
            if state == True:
                loop = asyncio.get_event_loop()
                #print(html)
                html = str(loop.run_until_complete(self.hello(url)))
                #print(html)
            else:
                html = self.get_url(url)
                
            soup = BeautifulSoup(html, 'html.parser') # todo get json requests
            IGNORED_EXTENSIONS = (
                '.jpg', '.jpeg', '.png', '.css', '.js', '.ico',
                '.doc', '.docx', '.pdf', '.mp4' , '.mov' , '.avi' , '.gif', '.jfif', '.woff2' , '.woff'
            )

            ARCHIVE_EXTENSIONS = (
                '.ecc', '.txt', '.par', '.war', '.tlz', '.lz', '.tgz', '.gz',
                '.zip', '.cfs', '.dar', '.jar', '.pak', '.rar', '.7z', '.iso',
                '.tar', '.br'
            )

            BACKUP_KEYWORDS = [
                "/backup", "/backupfile", "/backups", "/back", "/old", "/bk",
                "/config", "/backupsite", "/wwwroot", "/export", "/exports",
                "/latest", "/configs", "/mysql", "/server", "/uploads", "/upload",
                "/install", "/installer", "/database", "/db", "/error_log", "/access_log",
                "/admin", "/new", "/templates", "/archive", "/html", "/test",
                "/config.php", "/dump", "/web", "/sql", "/wp-config.php",
                "/log", "/setup", "/site", "/modules", "/backend", "/lib", "/src",
                "/changes", "/all", "/report"
            ]
            qualify_tags = ['a',
                'atom:link',
                'iframe',
                'img',
                'link',
                ]
            for tag in qualify_tags:
                for link in soup.find_all(tag):
                    path = link.get('href') or link.get('src')
                    if not path:
                        continue
                    if any(bk in path.lower() for bk in BACKUP_KEYWORDS):
                        if not path.lower().endswith(IGNORED_EXTENSIONS) and "image" not in path.lower() and not path.lower().startswith(('http', 'data:', 'mailto:', base_url)):
                            SQL_Insert_Query(
                                "INSERT INTO findbackup_tbl(usertoken,url) VALUES (%s,%s)",
                                (jobtoken, path)
                            )
                    if not path.lower().startswith(('http', 'data:', 'mailto:')) and path.lower().endswith(ARCHIVE_EXTENSIONS):
                        SQL_Insert_Query(
                            "INSERT INTO findbackup_tbl(usertoken,url) VALUES (%s,%s)",
                            (jobtoken, path)
                        )
                    if any(path.lower().endswith(bk) for bk in IGNORED_EXTENSIONS):
                        continue
                    if not path.lower().startswith(('http', 'data:', 'mailto:')) and not url.lower().endswith(path.lower()):
                        full_path = safe_urljoin(url, path)
                        self.append_url_to_visit(full_path)
                    elif urlparse(url.lower()).hostname == urlparse(path.lower()).hostname:
                        self.append_url_to_visit(path)
                        
            for form in soup.find_all("form"):
                exform = self.check_duplicate_forms(self.get_form_details(form))
        except Exception as e:
            print(e)
            pass

    def run(self):
        state = True
        global jobtoken
        print(f'******Job Token {jobtoken}******')
        while self.urls_to_visit:
            url = self.urls_to_visit.pop(0)
            self.visited_urls.add(url)
            try:
                
                self.crawl(url, state)
                state = False
            except ValueError:
                print(f'loading.....')
                
            
            print(f'Crawling through: {url}')
            self.extract_get_values(url)
            #print(f'Crawling 1')
            try:
                form = self.form_log_list.pop(0)
                #print(f'Crawling 2')
                #form = False
                if form:
                    base_query = "INSERT INTO crawlprofile_tbl(usertoken,url,methodtype,inputtype,inputs,encodedinputs) VALUES (%s,%s,%s,%s,%s,%s)"

                    params = parse_query_string_to_dict(form['inputs'])
                    testInput = form['inputs']
                    encodeType = 'PLAIN'
                    if params:
                        for k, v in params.items():
                            if v:
                                x,t = detect_and_decode(v)
                                if t:
                                    encodeType = t
                                    testInput = update_input_value(testInput, k, x)
                    values = (jobtoken,form['action'],form['method'].upper(),encodeType,form['inputs'],testInput) # todo find out inputs encoding // done
                    SQL_Insert_Query(base_query,values)
                    #print(f'[***FORMS**] {form}\r\n')
                    if "pass" in form['inputs'].lower():
                        base_query = "INSERT INTO findlogin_tbl(usertoken,url,methodtype,inputtype,inputs,status,iscaptcha) VALUES (%s,%s,%s,%s,%s,%s,%s)"
                        values = (jobtoken,form['action'],form['method'].upper(),'Plain',form['inputs'],200,False) # todo find out captcha enabaled
                        SQL_Insert_Query(base_query,values)
            except:
               # print("Error 1")
                pass
    
def startConfig(domain, token):
    global jobtoken, base_url
    jobtoken = token
    webpage = WebPage.new_from_url(domain)
    wappalyzer = Wappalyzer.latest()
    info = wappalyzer.analyze_with_versions(webpage)
    
    base_query = "INSERT INTO baseprofile_tbl(sitebaseurl,targetIP,servertype_programLang,usertoken) VALUES (%s,%s,%s,%s)"
    values = (domain,socket.gethostbyname(domain.replace("http://", "").replace("https://", "").replace(" ","").split('/')[0]),str(info),jobtoken);
    SQL_Insert_Query(base_query,values)
    base_url = domain
    
    values = (jobtoken,0)
    base_query = "INSERT INTO testsstat(token,stat) VALUES (%s,%s)"
    SQL_Insert_Query(base_query,values)
    
    Crawler(urls=[domain]).run()
    
    values = (1,jobtoken)
    base_query = "UPDATE testsstat SET stat=%s WHERE token=%s;"
    SQL_Insert_Query(base_query,values)
    time.sleep(5)
    #run_script(args.domain,jobtoken)
    SQL_Query(jobtoken)
    values = (2,jobtoken)
    base_query = "UPDATE testsstat SET stat=%s WHERE token=%s;"
    SQL_Insert_Query(base_query,values)
    
if __name__ == '__main__':
    print(f"""
    _______  ______ _______ _  _  _             _____ __   _      _____ _______
    |       |_____/ |_____| |  |  | |             |   | \  |        |      |   
    |_____  |    \_ |     | |__|__| |_____      __|__ |  \_|      __|__    |   
    by Mantis
    """)

    parser.add_argument("-d", "--domain", help = "Domain to crawl")
    parser.add_argument("-t", "--token", help = "User token")
    #parser.add_argument("-o", "--output", help = "Save results to file")
    args = parser.parse_args()
    startConfig(args.domain, args.token)
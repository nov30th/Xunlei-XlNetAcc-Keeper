import base64
import hashlib
import json
import random
import re
import sys
import time
import uuid
from threading import Timer
from typing import Dict
from urllib.parse import unquote

import requests
from requests_toolbelt import MultipartEncoder  # pip3 install requests-toolbelt

APP_VERSION = "2.4.1.3"
PROTOCOL_VERSION = 200
PEER_ID = ''
DEVICE = "SmallRice R1"
DEVICE_MODEL = "R1"
OS_VERSION = "5.0.1"
OS_API_LEVEL = "24"
OS_BUILD = "LRX22C"
header_xl = {
    'Content-Type': '',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'User-Agent': 'android-async-http/xl-acc-sdk/version-2.1.1.177662'
}
mobile_cookies = {}
device_sign = ""


class KuaiNiao_Session:
    def login_xunlei(self, uname, pwd):

        # pwd = rsa_encode(pwd_md5)
        fake_device_id = hashlib.md5(("msfdc%s23333" % pwd).encode('utf-8')).hexdigest()  # just generate a 32bit string
        # sign = div.10?.device_id + md5(sha1(packageName + businessType + md5(a protocolVersion specific GUID)))
        global device_sign
        device_sign = "div101.%s%s" % (fake_device_id, hashlib.md5(
            hashlib.sha1(("%scom.xunlei.vip.swjsq68c7f21687eed3cdb400ca11fc2263c998" % fake_device_id).encode('utf-8'))
            .hexdigest().encode('utf-8')
        ).hexdigest())
        _payload = {
            "protocolVersion": str(PROTOCOL_VERSION),
            "sequenceNo": "1000001",
            "platformVersion": "2",
            "sdkVersion": "177662",
            "peerID": PEER_ID,
            "businessType": "68",
            "clientVersion": APP_VERSION,
            "devicesign": device_sign,
            "isCompressed": "0",
            # "cmdID": 1,
            "userName": uname,
            "passWord": pwd,
            # "loginType": 0, # normal account
            "sessionID": "",
            "verifyKey": "",
            "verifyCode": "",
            "appName": "ANDROID-com.xunlei.vip.swjsq",
            # "rsaKey": {
            #    "e": "%06X" % rsa_pubexp,
            #    "n": long2hex(rsa_mod)
            # },
            # "extensionList": "",
            "deviceModel": DEVICE_MODEL,
            "deviceName": DEVICE,
            "OSVersion": OS_VERSION
        }
        ct = self.http_req('https://mobile-login.xunlei.com:443/login', body=json.dumps(_payload), headers=header_xl,
                           encoding='utf-8')
        self.xl_login_payload = _payload
        dt = json.loads(ct)

        self.load_xl(dt)
        return dt

    def load_xl(self, dt):
        if 'sessionID' in dt:
            self.xl_session = dt['sessionID']
        if 'userID' in dt:
            self.xl_uid = dt['userID']
        if 'loginKey' in dt:
            self.xl_loginkey = dt['loginKey']

    def http_req(self, url, headers={}, body=None, encoding='utf-8'):
        # req = urllib2.Request(url)
        # for k in headers:
        #     req.add_header(k, headers[k])
        if sys.version.startswith('3') and isinstance(body, str):
            body = bytes(body, encoding='ascii')
        resp = http_client.post(url, data=body, headers=headers)
        # resp = urllib2.urlopen(req, data=body, timeout=60)
        return resp.text
        # buf = resp.text
        # # check if response is gzip encoded
        # # if buf.startswith(b'\037\213'):
        # #     try:
        # #         buf = zlib.decompress(buf, 16 + zlib.MAX_WBITS)  # skip gzip headers
        # #     except Exception as ex:
        # #         print('Warning: malformed gzip response (%s).' % str(ex))
        # #         # buf is unchanged
        # # ret = buf.decode(encoding)
        # # if sys.version.startswith('3') and isinstance(ret, bytes):
        # #     ret = str(ret)
        # return ret


http_client = requests.session()


class KuaiNiao_Client:

    def __init__(self):
        # Base Funciton
        self._time_int = lambda: int(time.time())
        self._random_uuid4 = lambda: str(uuid.uuid4())
        self._random_int = lambda: random.randint(10000000, 99999999)
        self._getRealIP = lambda iptext: re.findall(
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", iptext)[0]
        # InitData
        self._status = -1  # -1 未初始化
        self._default_header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36",
        }
        self._httpclient = http_client  # requests.session()
        self._sdkInfo = self.GetWebSdkInfo()
        self._peerid = ""
        self._sequence = ""
        # self.getCookies()
        self.getCookies2(mobile_cookies)
        if self._peerid == "":
            self._peerid = PEER_ID  # self._cookies["kn-speed-peer-id"]
        if self._sequence == "":
            self._sequence = self._random_int()
        self._dsq = self.DownSpeedQuery()
        self._bwq = self.BandwidthInfo()

    def showInitMsg(self):
        dsq = self._dsq
        bwq = self._bwq
        print(
            '''------------------------------
当前用户:%s
状态:%s
当前网络状态:%s%s IP:%s
宽带账户:%s 允许提速:%s
签约带宽:%sM 预计提升速度:%sM
------------------------------''' % (
                unquote(self._cookies["usernick"]),
                self.PingUser()["msg"],
                dsq["sp_name"], dsq["province_name"], dsq["interface_ip"],
                bwq["dial_account"], bool(bwq["can_upgrade"]),
                str(bwq["bandwidth"]["downstream"] /
                    1024), str(bwq["max_bandwidth"]["downstream"] / 1024)
            ))

    # 初始化账户Cookies

    def getCookies(self):
        cookies = ''
        with open("./cookies.txt", "r+", encoding="utf-8") as cf:
            cookies = cf.read()
            pass
        cookies = json.loads(base64.b64decode(cookies).decode('utf-8'))
        requests.utils.add_dict_to_cookiejar(self._httpclient.cookies, cookies)
        self._cookies = cookies
        return cookies

    def getCookies2(self, cookies: Dict[str, str]):
        new_cookies: Dict[str, str] = {}
        for k, v in cookies.items():
            if k.lower() == "viplist":
                continue
            if k.lower() == "nickname":
                new_cookies["usernick"] = v
            new_cookies[k.lower()] = str(v)
        requests.utils.add_dict_to_cookiejar(self._httpclient.cookies, new_cookies)
        self._cookies = new_cookies
        return cookies

    def GetWebSdkInfo(self):
        params = {
            "ctype": "websdk",
            "ckey": "rules",
            "format": "json"
        }
        return self._httpclient.get("https://xluser-ssl.xunlei.com/config/v1/PubGetOne", params=params,
                                    headers=self._default_header).json()

    # 用户心跳包
    def PingUser(self):
        params = {
            "appid": "101",
            "appName": "WEB-k.xunlei.com",
            "deviceModel": "chrome/79.0.3945.130",
            "deviceName": "PC-Chrome",
            "hl": "",
            "OSVersion": "Win32",
            "provideName": "NONE",
            "netWorkType": "NONE",
            "providerName": "NONE",
            "sdkVersion": self._sdkInfo['data']["defaultVersion"],
            "clientVersion": "NONE",
            "protocolVersion": "300",
            "devicesign": device_sign,
            "platformVersion": "1",
            "fromPlatformVersion": "1",
            "format": "cookie",
            "timestamp": "self._time_int()",
            "userID": self._cookies["userid"],
            "sessionID": self._cookies["sessionid"],
        }
        data = MultipartEncoder(
            fields=params, boundary='----WebKitFormBoundarytZTJQrWcjjcJIMVQ')
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36",
            "Cache-Control": "no-cache",
            "Accept": "*/*",
            "authority": "xluser-ssl.xunlei.com",
            'Content-Type': data.content_type,
            "method": "POST",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "path": "/xluser.core.login/v3/ping",
            "scheme": "https",
        }
        result = self._httpclient.post(
            "http://xluser-ssl.xunlei.com/xluser.core.login/v3/ping", data=data, headers=headers)
        if result.status_code == 200:
            if result.text == "":
                return {"status": "Login", "msg": "用户保持在线中..."}
            else:
                try:
                    r = result.json()
                    r["status"] = "Logout"
                    r["msg"] = "用户离线."
                    return r
                except:
                    return {"status": "UnkownError", "msg": "异常错误:" + result.text}
        else:
            return {"status": "UnkownError", "msg": "异常错误:" + result.text}

    def DownSpeedQuery(self):
        params = {
            "host": "api.portal.swjsq.vip.xunlei.com",
            "port": "81",
            "callback": "",
            "sequence": self._sequence,
            "peerid": self._peerid,
            "sessionid": self._cookies["sessionid"],
            "userid": self._cookies["userid"],
            "client_type": "kn-speed",
            "client_version": "2.0.0",
            "_": self._time_int()
        }
        result = self._httpclient.get(
            "https://xlkn-ssl.xunlei.com/queryportal", params=params, headers=self._default_header).json()
        # realip = self._getRealIP(
        #    self._httpclient.get("http://ip.3322.net").text)
        # if result["interface_ip"] != realip:
        #    print("[Info]:FixRealIP:%s->%s" % (result["interface_ip"], realip))
        #    result["interface_ip"] = realip
        return result

    def UPSpeedQuery(self):
        params = {
            "host": "upspeed.swjsq.xunlei.com",
            "port": "80",
            "callback": "",
            "sequence": self._sequence,
            "peerid": self._peerid,
            "sessionid": self._cookies["sessionid"],
            "userid": self._cookies["userid"],
            "client_type": "kn-speed",
            "client_version": "2.0.0",
            "_": self._time_int()
        }
        return self._httpclient.get("https://upspeed-swjsq-ssl.xunlei.com/queryportal", params=params,
                                    headers=self._default_header).json()

    def BandwidthInfo(self):
        downspeedquery = self._dsq
        params = {
            "host": downspeedquery["interface_ip"],
            "port": downspeedquery["interface_port"],
            "callback": "",
            "sequence": self._sequence,
            "peerid": self._peerid,
            "sessionid": self._cookies["sessionid"],
            "userid": self._cookies["userid"],
            "client_type": "kn-speed",
            "client_version": "2.0.0",
            "_": self._time_int()
        }
        result = self._httpclient.get(
            "https://xlkn-ssl.xunlei.com/bandwidth", params=params, headers=self._default_header).json()
        if result["errno"] != 0:
            print("[Error]:" + result["richmessage"])
        return result

    def GetNoLoginBandwidthInfo(self):
        downspeedquery = self._dsq
        params = {
            "host": downspeedquery["interface_ip"],
            "port": downspeedquery["interface_port"],
            "callback": "",
            "sequence": self._random_int(),
            "peerid": self._random_uuid4(),
            "sessionid": "",
            "userid": "",
            "client_type": "kn-speed",
            "client_version": "2.0.0",
            "_": self._time_int()
        }
        result = requests.get("https://xlkn-ssl.xunlei.com/bandwidth",
                              params=params, headers=self._default_header).json()
        return result

    def UpgradeBW(self):
        self._dsq = self.DownSpeedQuery()
        self._bwq = self.BandwidthInfo()
        downspeedquery = self._dsq
        bwq = self._bwq
        params = {
            "host": downspeedquery["interface_ip"],
            "port": downspeedquery["interface_port"],
            "user_type": 1,
            "dial_account": bwq["dial_account"],
            "callback": "",
            "sequence": self._sequence,
            "peerid": self._peerid,
            "sessionid": self._cookies["sessionid"],
            "userid": self._cookies["userid"],
            "client_type": "kn-speed",
            "client_version": "2.0.0",
            "_": self._time_int()
        }
        result = self._httpclient.get(
            "https://xlkn-ssl.xunlei.com/upgrade", params=params, headers=self._default_header).json()
        self.lastUpgradeMsg = result["message"]
        return result

    def RecoverBW(self):
        self._dsq = self.DownSpeedQuery()
        self._bwq = self.BandwidthInfo()
        downspeedquery = self._dsq
        bwq = self._bwq
        params = {
            "host": downspeedquery["interface_ip"],
            "port": downspeedquery["interface_port"],
            "dial_account": bwq["dial_account"],
            "callback": "",
            "sequence": self._sequence,
            "peerid": self._peerid,
            "sessionid": self._cookies["sessionid"],
            "userid": self._cookies["userid"],
            "client_type": "kn-speed",
            "client_version": "2.0.0",
            "_": self._time_int()
        }
        result = self._httpclient.get(
            "https://xlkn-ssl.xunlei.com/recover", params=params, headers=self._default_header).json()
        if result["errno"] == 0:
            result["message"] = "下线成功!"
        return result


wait_t_arr = []


def set_interval(func, sec):
    def func_wrapper():
        set_interval(func, sec)
        func()

    t = Timer(sec, func_wrapper)
    t.start()
    wait_t_arr.append(t)
    return t


def update_speedup(kn_c):
    kn_c.showInitMsg()
    bwg_info = kn_c.GetNoLoginBandwidthInfo()
    if bwg_info["errno"] == 6020:
        print(bwg_info["message"])
    else:
        print("[Info]:" + kn_c.UpgradeBW()["message"])


def restart():
    global kn_c, mobile_cookies
    kn_c.RecoverBW()
    time.sleep(60)
    mobile_cookies = login()
    kn_c = KuaiNiao_Client()
    update_speedup(kn_c)


def login() -> str:
    with open("./userpwd.txt", "r+", encoding="utf-8") as cf:
        user_pwd = cf.read()
        pass
    with open("./peerid.txt", "r+", encoding="utf-8") as cf:
        global PEER_ID
        PEER_ID = cf.read()
        pass
    xunlei_login = KuaiNiao_Session()
    return xunlei_login.login_xunlei(user_pwd.split('|')[0], user_pwd.split('|')[1])


if __name__ == "__main__":
    mobile_cookies = login()
    kn_c = KuaiNiao_Client()
    print("[Info]:" + kn_c.RecoverBW()["message"])
    time.sleep(60)
    # kn_c = KuaiNiao_Client()
    # print(kn_c.PingUser())
    # print(kn_c.GetWebSdkInfo())
    # print(kn_c.DownSpeedQuery())
    # print(kn_c.UPSpeedQuery())
    # print(kn_c.BandwidthInfo())
    # print(kn_c.UpgradeBW())
    update_speedup(kn_c)
    set_interval(lambda: print("[Info]:" + kn_c.PingUser()["msg"]), 60 * 5)
    # set_interval(lambda: update_speedup(kn_c), 60 * 60 * 1.1)
    set_interval(lambda: restart(), 60 * 60 * 2.1)

    for t in wait_t_arr:
        t.join()
    input("Quit...")

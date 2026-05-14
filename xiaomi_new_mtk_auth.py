#!/usr/bin/env python3
import os
import shutil
import uuid

def get_pip_command():
    if shutil.which("pip3"):
        return "pip3"
    elif shutil.which("pip"):
        return "pip"
    else:
        raise EnvironmentError("NO,PIP")

for lib in ['Cryptodome', 'urllib3', 'requests', 'colorama']:
    try:
        __import__(lib)
    except ImportError:
        prefix = os.getenv("PREFIX", "")
        pip_cmd = get_pip_command()
        if lib == 'Cryptodome':
            if "com.termux" in prefix:
                cmd = 'pkg install python-pycryptodomex'
            else:
                cmd = f'{pip_cmd} install pycryptodomex'
        else:
            cmd = f'{pip_cmd} install {lib}'
        os.system(cmd)

import requests, json, hmac, random, binascii, urllib, hashlib, urllib.parse, shutil
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from urllib.parse import urlparse, parse_qs
from colorama import init, Fore, Style
init(autoreset=True)

cg = Style.BRIGHT + Fore.GREEN
cr = Fore.RED
cy = Style.BRIGHT + Fore.YELLOW
cb = Style.BRIGHT + Fore.BLUE
cres = Style.RESET_ALL

class XiaomiMtkTool:
    def __init__(self):
        self.session = requests.Session()
        self.headers = {"User-Agent": "XiaomiPCSuite"}
        
        self.config_dir = os.environ.get("XDG_CONFIG_HOME", os.path.join(os.path.expanduser("~"), ".config"))
        self.data_dir = os.path.join(self.config_dir, "xiaomi_gettoken")
        os.makedirs(self.data_dir, exist_ok=True)
        self.datafile = os.path.join(self.data_dir, "xiaomi_token.json")
        
        self.auth_info = {}
        self.ssecurity = None
        self.nonce = None
        self.cookies = {}
        
        self.current_host = "unlock.update.miui.com"
    
    def check_existing_login(self):
        if not os.path.isfile(self.datafile):
            return False
        
        try:
            with open(self.datafile, "r") as file:
                data = json.load(file)
            
            if data and data.get("login") == "ok":
                print(f"\n{cy}检测到已保存的账户: {data.get('userid', 'Unknown')}{cres}")
                choice = input(f"{cg}是否使用此账户? (y/N): {cres}").strip().lower()
                
                if choice == 'y':
                    if data.get("full_token"):
                        return self.login_with_full_token(data["full_token"])
                    elif data.get("passtoken") and data.get("userid"):
                        return self.login_with_saved_passtoken(data)
                    else:
                        print(f"{cr}保存的登录信息不完整{cres}")
                        os.remove(self.datafile)
                        return False
                elif choice == '删除':
                    print(f"{cy}删除保存的登录信息...{cres}")
                    os.remove(self.datafile)
                    return False
                else:
                    return False
            else:
                os.remove(self.datafile)
                return False
                
        except (PermissionError, json.JSONDecodeError):
            if os.path.exists(self.datafile):
                os.remove(self.datafile)
            return False
    
    def decode_full_token(self, token_b64):
        try:
            token_json = b64decode(token_b64).decode('utf-8')
            token_data = json.loads(token_json)
            return token_data
        except Exception as e:
            print(f"{cr}解码token失败: {e}{cres}")
            return None
    
    def login_with_full_token(self, token_b64):
        token_data = self.decode_full_token(token_b64)
        if not token_data:
            return False
        
        passToken = token_data.get("passToken")
        userId = token_data.get("userId")
        deviceId = token_data.get("deviceId")
        
        if not passToken or not userId:
            print(f"{cr}token中缺少必要的参数{cres}")
            return False
        
        print(f"{cg}Token解码成功{cres}")
        return self.request_auth_service(passToken, userId, deviceId)
    
    def login_with_saved_passtoken(self, data):
        passToken = data.get("passtoken")
        userId = data.get("userid")
        
        if not passToken or not userId:
            print(f"{cr}保存的登录信息不完整{cres}")
            os.remove(self.datafile)
            return False
        
        deviceId = ''.join(random.choices('0123456789abcdef', k=16))
        return self.request_auth_service(passToken, userId, deviceId)
    
    def request_auth_service(self, passToken, userId, deviceId):
        print(f"{cy}请求认证服务信息...{cres}")
        
        auth_response = self.session.get(
            "https://account.xiaomi.com/pass/serviceLogin?sid=unlockApi&_json=true&passive=true&hidden=true",
            headers=self.headers,
            cookies={
                'passToken': passToken,
                'userId': userId,
                'deviceId': deviceId
            }
        )
        
        try:
            auth_data = json.loads(auth_response.text.replace("&&&START&&&", ""))
        except:
            print(f"{cr}解析服务响应失败{cres}")
            return False
        
        if auth_data.get("code") != 0:
            error_msg = auth_data.get("desc", "未知错误")
            print(f"{cr}服务返回错误: {error_msg}{cres}")
            return False
        
        if "ssecurity" not in auth_data:
            print(f"{cr}无法获取ssecurity参数!{cres}")
            return False
        
        if "location" not in auth_data:
            print(f"{cr}无法获取location参数!{cres}")
            return False
        
        location_url = auth_data["location"]
        parsed_url = urlparse(location_url)
        query_params = parse_qs(parsed_url.query)
        
        nonce = query_params.get('nonce', [None])[0]
        if not nonce:
            print(f"{cr}无法从location中获取nonce参数!{cres}")
            return False
        
        self.ssecurity = auth_data["ssecurity"]
        self.nonce = nonce
        
        return self.complete_authentication(location_url, userId, passToken)
    
    def complete_authentication(self, location_url, userId, passToken):
        print(f"{cy}完成认证流程...{cres}")
        
        client_sign = urllib.parse.quote_plus(
            b64encode(
                hashlib.sha1(f"nonce={self.nonce}".encode("utf-8") + b"&" + self.ssecurity.encode("utf-8")).digest()
            )
        )
        
        response = self.session.get(
            location_url + "&clientSign=" + client_sign,
            headers=self.headers
        )
        
        self.cookies = {cookie.name: cookie.value for cookie in response.cookies}
        
        if 'serviceToken' not in self.cookies:
            print(f"{cr}获取serviceToken失败.{cres}")
            return False
        
        self.auth_info = {
            "login": "ok",
            "userid": userId,
            "passtoken": passToken,
            "ssecurity": self.ssecurity,
            "nonce": self.nonce,
            "passtoken_used": True
        }
        self.save_data(self.auth_info)
        
        print(f"\n{cg}DONE！登录成功!{cres}")
        print(f"{cg}账户信息:{cres}\nID: {userId}")
        
        return True
    
    def hex_to_base64(self, hex_string):
        try:
            hex_string = hex_string.strip()
            bytes_data = bytes.fromhex(hex_string)
            base64_data = b64encode(bytes_data).decode('utf-8')
            return base64_data
        except Exception as e:
            print(f"{cr}十六进制转换失败: {e}{cres}")
            return None
    
    def authenticate_with_full_token(self):
        print(f"\n{cy}使用完整token登录{cres}")
        
        print(f"{cb}请输入完整的token字符串:{cres}")
        print(f"{cy}格式: base64编码的JSON或十六进制字符串{cres}")
        
        token_input = input(f"\n{cy}请输入token: {cres}").strip()
        
        if not token_input:
            print(f"{cr}token不能为空{cres}")
            return False
        
        token_b64 = None
        try:
            if all(c in '0123456789abcdefABCDEF' for c in token_input):
                print(f"{cy}检测到十六进制token，正在转换...{cres}")
                token_b64 = self.hex_to_base64(token_input)
                if not token_b64:
                    return False
            else:
                token_b64 = token_input
        except:
            token_b64 = token_input
        
        token_data = self.decode_full_token(token_b64)
        if not token_data:
            return False
        
        passToken = token_data.get("passToken")
        userId = token_data.get("userId")
        deviceId = token_data.get("deviceId")
        
        if not passToken or not userId:
            print(f"{cr}token中缺少passToken或userId{cres}")
            return False
        
        if not deviceId:
            deviceId = ''.join(random.choices('0123456789abcdef', k=16))
        
        self.auth_info = {
            "login": "ok",
            "userid": userId,
            "full_token": token_b64,
            "passtoken_used": True
        }
        
        return self.request_auth_service(passToken, userId, deviceId)
    
    def authenticate_with_passtoken(self):
        print(f"\n{cy}使用passtoken登录{cres}")
        
        print(f"{cb}步骤1: 获取passtoken{cres}")
        print(f"{cy}请按以下步骤操作:{cres}")
        print(f"1. 打开浏览器访问: {cb}https://account.xiaomi.com{cres}")
        print(f"2. 登录您的小米账户")
        print(f"3. 按F12打开开发者工具")
        print(f"4. 进入Application/Storage标签页")
        print(f"5. 在Cookies中找到 {cb}passToken{cres} 的值")
        print(f"6. 同时找到 {cb}userId{cres} 的值")
        
        passToken = input(f"\n{cy}请输入passToken: {cres}").strip()
        userId = input(f"{cy}请输入userId: {cres}").strip()
        
        if not passToken or not userId:
            print(f"{cr}passToken和userId不能为空{cres}")
            return False
        
        deviceId = ''.join(random.choices('0123456789abcdef', k=16))
        
        return self.request_auth_service(passToken, userId, deviceId)
    
    def save_data(self, data):
        with open(self.datafile, "w") as file:
            json.dump(data, file, indent=2)
    
    def get_device_info(self):
        print(f"\n{cy}获取设备信息{cres}")
        print(f"{cb}请粘贴第三方工具获取的加密base64 token{cres}")
        b64_data = input(f"{cy}token: {cres}").strip()
        
        if not b64_data:
            print(f"{cr}输入不能为空{cres}")
            return None, None, None
        
        try:
            decoded = b64decode(b64_data).decode('utf-8')
            info = json.loads(decoded)
            projectname = info.get("projectname")
            platformname = info.get("platformname")
            blob = info.get("blob")
            
            if not all([projectname, platformname, blob]):
                print(f"{cr}token缺少参数{cres}")
                return None, None, None
            
            return platformname, projectname, blob   # socname, daihao, token
        except Exception as e:
            print(f"{cr}token解析失败: {e}{cres}")
            return None, None, None

    class RetrieveEncryptData:
        def __init__(self, mtk_api, path, params):
            self.mtk_api = mtk_api
            self.path = path
            self.params = {k.encode("utf-8"): 
                (v.encode("utf-8") if isinstance(v, str) 
                 else b64encode(json.dumps(v).encode("utf-8")) if not isinstance(v, bytes) 
                 else v) 
                for k, v in params.items()}
        
        def add_nonce(self):
            print(f"{cy}获取nonce...{cres}")
            r = XiaomiMtkTool.RetrieveEncryptData(
                self.mtk_api,
                "/api/v2/nonce", 
                {
                    "r": ''.join(random.choices(list("abcdefghijklmnopqrstuvwxyz"), k=16)), 
                    "sid": "miui_unlocktool_client"
                }
            ).run()
            
            if r and "nonce" in r:
                self.params[b"nonce"] = r["nonce"].encode("utf-8")
                self.params[b"sid"] = b"miui_unlocktool_client"
                print(f"{cg}获取nonce成功{cres}")
            else:
                print(f"{cr}获取nonce失败: {r}{cres}")
                if hasattr(self.mtk_api, 'nonce') and self.mtk_api.nonce:
                    self.params[b"nonce"] = self.mtk_api.nonce.encode("utf-8")
                    self.params[b"sid"] = b"miui_unlocktool_client"
                    print(f"{cy}使用当前nonce继续{cres}")
                else:
                    raise Exception("无法获取nonce")
            
            return self
        
        def getp(self, sep):
            return b'POST' + sep + self.path.encode("utf-8") + sep + b"&".join([
                k + b"=" + v for k, v in self.params.items()
            ])
        
        def run(self):
            try:
                if not self.mtk_api.ssecurity:
                    return {"error": "ssecurity为空，请重新登录"}
                
                self.params[b"sign"] = binascii.hexlify(
                    hmac.digest(
                        b'2tBeoEyJTunmWUGq7bQH2Abn0k2NhhurOaqBfyxCuLVgn4AVj7swcawe53uDUno', 
                        self.getp(b"\n"), 
                        "sha1"
                    )
                )
                
                ssecurity_bytes = b64decode(self.mtk_api.ssecurity)
                
                for k, v in self.params.items():
                    padded_data = v + (16 - len(v) % 16) * bytes([16 - len(v) % 16])
                    encrypted = AES.new(ssecurity_bytes, AES.MODE_CBC, b"0102030405060708").encrypt(padded_data)
                    self.params[k] = b64encode(encrypted)
                
                self.params[b"signature"] = b64encode(
                    hashlib.sha1(
                        self.getp(b"&") + b"&" + self.mtk_api.ssecurity.encode("utf-8")
                    ).digest()
                )
                
                post_data = {}
                for k, v in self.params.items():
                    post_data[k.decode('utf-8')] = v.decode('utf-8')
                
                url = f"https://{self.mtk_api.current_host}{self.path}"
                
                response = self.mtk_api.session.post(
                    url, 
                    data=post_data,
                    headers=self.mtk_api.headers, 
                    cookies=self.mtk_api.cookies,
                    timeout=30
                )
                                
                if not response.text.strip():
                    return {"error": "服务器返回空响应"}
                
                try:
                    decrypt_cipher = AES.new(ssecurity_bytes, AES.MODE_CBC, b"0102030405060708")
                    encrypted_response = b64decode(response.text)
                    decrypted = decrypt_cipher.decrypt(encrypted_response)
                    
                    decrypted = decrypted[:-decrypted[-1]]
                    
                    result = json.loads(b64decode(decrypted))
                    return result
                    
                except Exception as e:
                    print(f"{cr}解密响应失败: {e}{cres}")
                    try:
                        return json.loads(response.text)
                    except:
                        return {"error": f"解密失败: {e}", "raw_response": response.text}
                    
            except Exception as e:
                print(f"{cr}请求执行失败: {e}{cres}")
                return {"error": str(e)}
    
    def request_mtk(self, token, socname, daihao):
        print(f"\n{cy}正在开始加密请求数据...{cres}")
        print(f"\n{cy}正在算码...{cres}")
        
        userId = self.auth_info.get("userid")
        
        device_id = f"wb_{uuid.uuid4()}"
        pc_id = hashlib.md5(device_id.encode()).hexdigest()

        mtk_data = {
            "appId": "1",
            "data": {
                "SEClevel" : "0",
                "clientId": "mtkFlash",
                "cmdtype" : "1",
                "clientVersion": "5.3.1209.3",
                "flashToken": token,
                "paddingtype" : "1",
                "pattern" : "2",
                "pcId": pc_id,
                "platform" : socname,
                "project" : daihao,
                "uid": userId
            }
        }

        result = self.RetrieveEncryptData(
            self,
            "/api/v1/mtk/flash/ahaFlash",
            mtk_data
        ).add_nonce().run()
        
        return result
    
    def run(self):
        print(f"{cg}{'='*70}{cres}")
        print(f"{cb}                小米mtk新设备算命工具 {cres}")
        print(f"{cb}项目                https://github.com/bgm145632/xiaomi_auth_get_Mtk_sig{cres}")
        print(f"                                         {cres}")
        print(f"{cb}作者                          BEICHEN，bgm145632{cres}")
        print(f"{cr}提醒                          使用工具前确保同网络和地区否则后果自负{cres}")
        print(f"                                         {cres}")
        print(f"{cb}长风破浪会有时 直挂云帆济沧海{cres}")
        print(f"{cg}{'='*70}{cres}")
        
        try:
            if not self.check_existing_login():
                print(f"\n{cy}需要登录小米账户{cres}")
                print(f"{cy}请选择登录方式:{cres}")
                print(f"1. 使用完整token (推荐)")
                print(f"2. 使用passtoken和userid (需要保持浏览器账户没退出)")
                
                choice = input(f"\n{cy}请选择 (默认1): {cres}").strip() or "1"
                
                if choice == "1":
                    if not self.authenticate_with_full_token():
                        return
                else:
                    if not self.authenticate_with_passtoken():
                        return
            
            socname, daihao, device_token = self.get_device_info()
            if not all([socname, daihao, device_token]):
                print(f"{cr}设备信息不完整{cres}")
                return
            
            input(f"\n{cy}按 Enter 请求...{cres}")
            
            result = self.request_mtk(device_token, socname, daihao)
            
            if not result:
                print(f"{cr}请求失败 - 无响应{cres}")
                return
                
            print(f"\n{cy}服务器响应:{cres}")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            
            if "code" in result and result["code"] == 0:
                encrypt_data = result.get("encryptData")
                if encrypt_data and isinstance(encrypt_data, str) and len(encrypt_data) > 10:
                    print(f"\n{cg}sig获取成功!{cres}")
                    print(f"{cb}{'='*50}{cres}")
                    print(f"{cg}sig (encryptData):{cres}")
                    print(f"{cy}{encrypt_data}{cres}")
                    print(f"{cb}{'='*50}{cres}")
                    
                    print(f"\n{cy}请使用此sig在mtkv6工具开始授权{cres}")
                else:
                    print(f"{cr}响应中缺少有效的数据{cres}")
                    
            elif "descEN" in result:
                print(f"\n{cr}授权失败: {result['descCN']}{cres}")
            else:
                print(f"\n{cr}未知的响应格式{cres}")
            
            print(f"\n{cg}{'='*70}{cres}")
            print(f"{cg}                    流程完成!{cres}")
            print(f"{cg}{'='*70}{cres}")
            
        except KeyboardInterrupt:
            print(f"\n{cy}用户取消操作{cres}")
        except Exception as e:
            print(f"\n{cr}发生错误: {e}{cres}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    tool = XiaomiMtkTool()
    tool.run()
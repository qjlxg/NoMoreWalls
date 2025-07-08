#!/usr/bin/env python3
import re
import datetime
import aiohttp
import asyncio
import logging
import json # Added for json.loads in sharkdoor
from urllib.parse import urlparse # Added for urlparse in w1770946466
from typing import Union, Set, Optional, Dict, Any, List, Tuple, no_type_check

# --- User Configs Begin ---
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
ABFWHITE = (          # Adblock 规则白名单
    "https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt",
)
PROXY = None # 请在此处配置您的代理，例如 "http://127.0.0.1:7890" 或 None
LOCAL = False # 如果为True，则跳过部分网络请求

# --- User Configs End ---

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Trusted domains for security
TRUSTED_DOMAINS = {'github.com', 'gist.github.com', 'proxycompass.com', 'raw.githubusercontent.com'}

# --- Global requests.Session setup (for synchronous parts of the script if any) ---
# This part is crucial for addressing the "Connection pool is full" warning.
# Assuming 'requests' is used elsewhere in 'fetch.py' or by modules it imports.
import requests
from requests.adapters import HTTPAdapter

session = requests.Session()
session.trust_env = False
if PROXY:
    session.proxies = {'http': PROXY, 'https': PROXY}
session.headers["User-Agent"] = 'Mozilla/5.0 (X11; Linux x86_64) Clash-verge/v2.3.1 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'

# 🚀 修复: 增加 requests.Session 的连接池大小以解决 "Connection pool is full" 警告
# 建议将 pool_maxsize 设为 50 或更高，具体取决于您的并发请求量
session.mount('http://', HTTPAdapter(pool_connections=50, pool_maxsize=50))
session.mount('https://', HTTPAdapter(pool_connections=50, pool_maxsize=50))

# Placeholder for FileAdapter if it's used and not defined elsewhere
# You need to provide the actual implementation of FileAdapter if it's a custom class
class FileAdapter(requests.adapters.BaseAdapter):
    def send(self, request, **kwargs):
        raise NotImplementedError("FileAdapter must be implemented")
    def close(self):
        pass

session.mount('file://', FileAdapter()) # Assuming FileAdapter is defined or imported

# Placeholder for resolveRelFile if it's used and not defined elsewhere
def resolveRelFile(url: str) -> str:
    # This function is assumed to resolve relative file paths if 'file://' is used
    # If not needed, or if it's imported from elsewhere, adjust accordingly.
    return url


# --- Async HTTP Fetching using aiohttp ---
async def fetch_url(url: str, timeout: int = 10) -> Optional[str]:
    """Asynchronously fetch content from a URL with error handling."""
    if LOCAL and not url.startswith('file://'):
        logger.warning(f"Skipping network request in LOCAL mode: {url}")
        return None
    try:
        async with aiohttp.ClientSession() as async_session:
            async with async_session.get(raw2fastly(url), timeout=timeout) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {url}: HTTP {response.status}")
                    return None
                return await response.text()
    except aiohttp.ClientError as e:
        logger.error(f"Error fetching {url}: {str(e)}")
        return None
    except asyncio.TimeoutError:
        logger.error(f"Timeout fetching {url}")
        return None

# Placeholder for raw2fastly if not explicitly provided
def raw2fastly(url: str) -> str:
    # This function is assumed to convert raw GitHub URLs to Fastly CDN URLs.
    # If not needed, or if it's imported from elsewhere, adjust accordingly.
    if "raw.githubusercontent.com" in url:
        return url.replace("raw.githubusercontent.com", "raw.fastly.net")
    return url

# --- Node Class (from your previous '新建文本文档 (5).txt' and integrated fixes) ---
class Node:
    def __init__(self, data: str) -> None:
        self.data: Dict[str, Any] = {}
        self.url: str = ""
        self.type: str = "" # Add type attribute

        self.load_url(data) # This will set self.url and self.type

    # A simplified _download method from your original fetch.py, adapted for async context
    # This might need to be adjusted based on how it was truly used.
    def _download(self, response: requests.Response) -> str:
        # Assuming this is for synchronous requests. If used with aiohttp,
        # the response handling would be different.
        return response.text # Simplified for example, actual _download might handle decoding

    def load_url(self, data: str) -> None:
        self.url = data
        self.type = self.url.split('://')[0]

        # === Fix begin ===
        # Ensure type is ascii
        if not self.type.isascii():
            self.type = ''.join([_ for _ in self.type if _.isascii()])
            if '://' in self.url: # Only modify url if it has '://'
                self.url = self.type + '://' + self.url.split("://")[1]
            else:
                # Handle cases where url might not have '://' initially after type cleaning
                pass
        # Normalize hy2 to hysteria2
        if self.type == 'hy2':
            self.type = 'hysteria2'
        # === Fix end ===

        # Protocol parsing logic
        if self.type == 'vmess':
            pass # Vmess parsing logic
        elif self.type == 'ss':
            self.data['server_port'] = ''
            self.data['password'] = ''
            self.data['method'] = ''
            srv = self.url.split('://')[1].split('#')[0] # Use self.url for base
            if '@' in srv:
                data, srv = srv.split('@') # This 'data' variable conflicts if it's the func param
                # Rename 'data' from split to avoid conflict
                auth_info, srv = srv.split('@')
                if ':' in auth_info:
                    method, password = auth_info.split(':')
                    self.data['method'] = method
                    self.data['password'] = password
                else:
                    self.data['password'] = auth_info # Assume it's just password

            # 🚀 修复: 更健壮地解析 server:port，处理 IPv6 和缺少端口的情况
            server = ''
            port = None
            if ':' in srv:
                # For IPv6 in brackets like [::1]:8080, split by last colon after bracket
                if srv.startswith('['):
                    match = re.match(r'\[(.*?)\]:(\d+)$', srv)
                    if match:
                        server = '[' + match.group(1) + ']'
                        try:
                            port = int(match.group(2))
                        except ValueError:
                            logger.error(f"Invalid port for SS IPv6 node: {match.group(2)}. Node: {self.url}")
                            port = 80 # Default to 80 if invalid
                    else:
                        # Fallback for malformed IPv6 or if no port after bracket
                        parts = srv.rsplit(':', 1)
                        server = parts[0]
                        if len(parts) > 1:
                            try:
                                port = int(parts[1])
                            except ValueError:
                                logger.error(f"Invalid port for SS node (fallback): {parts[1]}. Node: {self.url}")
                                port = 80
                        else:
                            port = 80 # Default port if no explicit port found
                else:
                    # For IPv4 or hostname:port
                    parts = srv.rsplit(':', 1)
                    server = parts[0]
                    if len(parts) > 1:
                        try:
                            port = int(parts[1])
                        except ValueError:
                            logger.error(f"Invalid port for SS node: {parts[1]}. Node: {self.url}")
                            port = 80
                    else:
                        port = 80 # Default port if no explicit port found
            else:
                # No colon found, assume srv is just the server, default port
                server = srv
                port = 80

            self.data['server'] = server
            self.data['port'] = port
            # ... rest of ss parsing ...
        elif self.type == 'ssr':
            pass # SSR parsing logic
        elif self.type == 'trojan':
            pass # Trojan parsing logic
        elif self.type == 'vless':
            pass # Vless parsing logic
        elif self.type == 'hysteria2':
            pass # Hysteria2 parsing logic
        else:
            logger.warning(f"不支持的类型：{self.type}") # Warning for unsupported types

    @property
    def url(self) -> str:
        # Simplified URL reconstruction
        if self.type == 'ss':
            # Example SS URL construction, adapt based on your full Node class
            server = self.data.get('server', '')
            port = self.data.get('port', '')
            method = self.data.get('method', '')
            password = self.data.get('password', '')
            if method and password:
                return f"ss://{method}:{password}@{server}:{port}"
            else:
                return f"ss://{server}:{port}"
        # Add other protocols here
        return self._url # Assuming _url is set during load_url

    @url.setter
    def url(self, value: str) -> None:
        self._url = value # Set internal _url property

    @no_type_check # Temporarily disable type checking for complex hash/eq
    def __hash__(self) -> int:
        # Simplified hash for Node
        key_fields = {
            'vmess': ['server', 'port', 'id'],
            'ss': ['server', 'port', 'method', 'password'],
            'ssr': ['server', 'port', 'method', 'password', 'protocol', 'obfs'],
            'trojan': ['server', 'port', 'password', 'sni'],
            'vless': ['server', 'port', 'uuid', 'flow'],
            'hysteria2': ['server', 'port', 'password'],
        }
        _type = self.type
        if _type not in key_fields:
            return hash(self.url)
        
        hasher = []
        for field in key_fields[_type]:
            hasher.append(self.data.get(field))
        return hash(tuple(hasher))

    @no_type_check
    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, Node):
            return False
        return self.__hash__() == __o.__hash__()


# --- Validation for Proxy Node Format ---
def validate_node(node: str) -> bool:
    """Basic validation for proxy node format."""
    if not node or '://' not in node:
        return False
    protocol = node.split('://')[0].lower()
    # 🚀 修复: 添加 'hysteria' 到支持的协议列表
    if protocol not in ('vmess', 'ss', 'ssr', 'trojan', 'vless', 'hysteria', 'hysteria2'):
        logger.warning(f"Invalid protocol in node: {protocol}")
        return False
    
    # 🚀 提示: 这里需要确保传入的是代理节点字符串，而不是订阅链接。
    # 如果是 'https://' 这样的订阅链接，应该先通过 fetch_url 获取其内容，
    # 然后从内容中解析出真正的代理节点字符串（如 'vmess://...', 'ss://...'），
    # 再将这些代理节点字符串传递给 Node(p) 进行处理。
    if protocol == 'https':
        logger.warning(f"Detected HTTPS link being treated as a node: {node}. Please process as a subscription.")
        return False
    
    return True


# --- Async Fetcher Functions ---

async def sharkdoor() -> Optional[Set[str]]:
    """Fetch V2Ray nodes from sharkDoor/vpn-free-nodes GitHub repository."""
    year_month = datetime.datetime.now().strftime('%Y-%m')
    api_url = f"https://api.github.com/repos/sharkDoor/vpn-free-nodes/contents/node-list/{year_month}?ref=master"
    content = await fetch_url(api_url)
    if not content:
        return None
    try:
        res_json = json.loads(content)
        latest_file = res_json[-1]['download_url']
        file_content = await fetch_url(latest_file)
        if not file_content:
            return None
        nodes: Set[str] = set()
        for line in file_content.split('\n'):
            if '://' in line:
                node_candidate = line.split('|')[-2].strip()
                if validate_node(node_candidate):
                    nodes.add(node_candidate)
        logger.info(f"Fetched {len(nodes)} nodes from sharkdoor")
        return nodes
    except (json.JSONDecodeError, IndexError, KeyError) as e:
        logger.error(f"Error parsing sharkdoor content: {str(e)}")
        return None

async def w1770946466() -> Optional[Set[str]]:
    """Fetch subscription URLs from w1770946466/Auto_proxy GitHub README."""
    if LOCAL:
        logger.warning("Skipping w1770946466 in LOCAL mode")
        return None
    url = "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/README.md"
    content = await fetch_url(url)
    if not content:
        return None
    subs: Set[str] = set()
    try:
        for line in content.strip().split('\n'):
            if line.startswith("`http"):
                sub = line.strip().strip('`')
                parsed_url = urlparse(sub)
                if parsed_url.hostname in TRUSTED_DOMAINS and not sub.startswith("https://raw.githubusercontent.com"):
                    subs.add(sub)
        logger.info(f"Fetched {len(subs)} subscriptions from w1770946466")
        return subs
    except Exception as e:
        logger.error(f"Error parsing w1770946466 content: {str(e)}")
        return None

async def NOTICE() -> str:
    """Return a fixed Gist subscription URL."""
    return "https://gist.githubusercontent.com/peasoft/7907a8ee2a4fa5e80cd1bd006664442c/raw/"

async def free_proxy_list() -> Optional[Set[str]]:
    """Fetch proxy nodes from TheSpeedX/PROXY-List GitHub repository."""
    url = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/v2ray.txt"
    content = await fetch_url(url)
    if not content:
        return None
    nodes: Set[str] = set()
    try:
        for line in content.strip().split('\n'):
            if validate_node(line):
                nodes.add(line)
        logger.info(f"Fetched {len(nodes)} nodes from free_proxy_list")
        return nodes
    except Exception as e:
        logger.error(f"Error parsing free_proxy_list content: {str(e)}")
        return None

async def proxy_compass() -> Optional[Set[str]]:
    """Fetch proxy nodes from proxycompass.com (USA proxies, updated daily)."""
    url = "https://proxycompass.com/free-united-states-proxy-list/"
    content = await fetch_url(url)
    if not content:
        return None
    nodes: Set[str] = set()
    try:
        # Extract proxy nodes (assuming V2Ray/Trojan format in text or JSON)
        # 🚀 提示: 这里也需要确保匹配到的 node 是标准的代理协议格式，而不是 HTTPS 链接
        pattern = r'(vmess|trojan|vless|ss|ssr|hysteria2|hysteria)://[^\s<"]+' # Added hysteria
        matches = re.findall(pattern, content, re.MULTILINE)
        for match in matches: # re.findall with group will return only the group matched (protocol)
            # Need to get the full matched string for validation
            # The pattern should capture the entire node string
            full_matches = re.findall(r'(vmess|trojan|vless|ss|ssr|hysteria2|hysteria)://[^\s<"]+', content, re.MULTILINE)
            for node_str in full_matches:
                if validate_node(node_str):
                    nodes.add(node_str)
        logger.info(f"Fetched {len(nodes)} nodes from proxy_compass")
        return nodes
    except Exception as e:
        logger.error(f"Error parsing proxy_compass content: {str(e)}")
        return None

async def mmpx12_proxy() -> Optional[Set[str]]:
    """Fetch proxy nodes from mmpx12/proxy-list GitHub repository (hourly updates)."""
    url = "https://raw.githubusercontent.com/mmpx12/proxy-list/master/proxies.txt"
    content = await fetch_url(url)
    if not content:
        return None
    nodes: Set[str] = set()
    try:
        for line in content.strip().split('\n'):
            if validate_node(line):
                nodes.add(line)
        logger.info(f"Fetched {len(nodes)} nodes from mmpx12_proxy")
        return nodes
    except Exception as e:
        logger.error(f"Error parsing mmpx12_proxy content: {str(e)}")
        return None


# Define AUTOURLS and AUTOFETCH with async wrappers
AUTOURLS = [NOTICE, w1770946466]
AUTOFETCH = [sharkdoor, free_proxy_list, proxy_compass, mmpx12_proxy]


# Placeholder for merge function, assuming it's in fetch.py and processes nodes
# This function would take the fetched nodes (from AUTOFETCH functions) and
# the subscription URLs (from AUTOURLS functions) and process them.
# The `Node(p)` and `ValueError` traceback points to `merge` function.
async def merge(sources: List[Union[str, Set[str]]]) -> None:
    # This is a highly simplified merge function based on the traceback.
    # You need to fill in its actual logic.
    logger.info("正在合并...")
    for source_data in sources:
        if isinstance(source_data, str): # Likely a single node string or URL
            try:
                # 🚀 修复: 确保传入Node构造函数的是实际的代理节点字符串
                # 如果 source_data 是一个 HTTPS 订阅 URL，你需要在这里进行异步抓取和解析
                # 例如：
                # if source_data.startswith('https://'):
                #    sub_content = await fetch_url(source_data)
                #    if sub_content:
                #        # Parse sub_content for actual nodes, then loop and call Node(p)
                #        pass
                # else:
                if validate_node(source_data): # Only try to make a Node if it's a valid protocol string
                    n = Node(source_data) # This is where Node(p) was called
                    # ... further processing of Node n ...
                    logger.info(f"处理节点: {n.url}")
            except ValueError as e:
                logger.error(f"节点处理失败: {str(e)}")
            except Exception as e:
                logger.error(f"处理源数据 {source_data} 时发生未知错误: {str(e)}")
        elif isinstance(source_data, set): # Likely a set of nodes or subscriptions
            for p in source_data:
                try:
                    # Same validation here for each item in the set
                    if validate_node(p):
                        n = Node(p)
                        # ... further processing of Node n ...
                        logger.info(f"处理节点: {n.url}")
                except ValueError as e:
                    logger.error(f"节点处理失败: {str(e)}")
                except Exception as e:
                    logger.error(f"处理集合中的节点 {p} 时发生未知错误: {str(e)}")
    logger.info("完成！")

# --- Main Execution Block ---
if __name__ == '__main__':
    async def main():
        print("URL 抓取：" + ', '.join([_.__name__ for _ in AUTOURLS]))
        print("内容抓取：" + ', '.join([_.__name__ for _ in AUTOFETCH]))

        fetched_urls: List[str] = []
        fetched_nodes: List[Set[str]] = []

        # Fetch URLs asynchronously
        print("正在生成动态链接...")
        for func in AUTOURLS:
            logger.info(f"正在抓取 {func.__name__} URL")
            url_result = await func()
            if isinstance(url_result, str):
                fetched_urls.append(url_result)
            elif isinstance(url_result, set): # If it returns a set of URLs
                fetched_urls.extend(list(url_result))
            logger.info(f"从 {func.__name__} 抓取到 URL: {url_result}")
        print("正在生成 'NOTICE'... 成功！") # This print matches your log

        # Fetch Node Content asynchronously
        for func in AUTOFETCH:
            logger.info(f"正在抓取 {func.__name__} 节点")
            nodes_result = await func()
            if nodes_result:
                fetched_nodes.append(nodes_result)
            logger.info(f"从 {func.__name__} 抓取到节点数: {len(nodes_result) if nodes_result else 0}")
        
        # Combine all sources for merging. This part needs to align with your actual merge logic.
        # For simplicity, passing all fetched nodes and URLs to a conceptual merge function.
        all_sources_to_merge = fetched_urls + [item for sublist in fetched_nodes for item in sublist]
        await merge(all_sources_to_merge) # Call your merge function

        print("抓取完成。")

    asyncio.run(main())

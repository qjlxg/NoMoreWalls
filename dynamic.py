#!/usr/bin/env python3
import re
import datetime
import aiohttp
import asyncio
import logging
from typing import Union, Set, Optional
from fetch import raw2fastly, session, LOCAL

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Trusted domains for security
TRUSTED_DOMAINS = {'github.com', 'gist.github.com', 'proxycompass.com', 'raw.githubusercontent.com'}

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

def validate_node(node: str) -> bool:
    """Basic validation for proxy node format."""
    if not node or '://' not in node:
        return False
    protocol = node.split('://')[0].lower()
    if protocol not in ('vmess', 'ss', 'ssr', 'trojan', 'vless', 'hysteria2'):
        logger.warning(f"Invalid protocol in node: {protocol}")
        return False
    return True

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
                node = line.split('|')[-2].strip()
                if validate_node(node):
                    nodes.add(node)
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
        pattern = r'(vmess|trojan|vless|ss|ssr|hysteria2)://[^\s<"]+'
        matches = re.findall(pattern, content, re.MULTILINE)
        for node in matches:
            if validate_node(node):
                nodes.add(node)
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

if __name__ == '__main__':
    async def main():
        print("URL 抓取：" + ', '.join([_.__name__ for _ in AUTOURLS]))
        print("内容抓取：" + ', '.join([_.__name__ for _ in AUTOFETCH]))
        for func in AUTOURLS + AUTOFETCH:
            logger.info(f"Testing {func.__name__}")
            result = await func()
            logger.info(f"Result from {func.__name__}: {result}")

    asyncio.run(main())

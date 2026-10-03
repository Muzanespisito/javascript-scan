#!/usr/bin/env python3
"""JS Fetch - JavaScript URL security scanner - By MuZaN"""

import argparse
import re
import sys
import time
import os
import subprocess
from urllib.parse import urlparse


class bcolors:
    RED = '\033[91m'
    BLACK = '\033[90m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def gradient_text(text, color1="FF0000", color2="000000"):
    """Red -> Black gradient for beautiful appearance."""
    result = ""
    for i, char in enumerate(text):
        ratio = i / max(len(text) - 1, 1)
        r = int(int(color1[0:2], 16) + (int(color2[0:2], 16) - int(color1[0:2], 16)) * ratio)
        g = int(int(color1[2:4], 16) + (int(color2[2:4], 16) - int(color1[2:4], 16)) * ratio)
        b = int(int(color1[4:6], 16) + (int(color2[4:6], 16) - int(color1[4:6], 16)) * ratio)
        result += f"\033[38;2;{r};{g};{b}m{char}"
    result += bcolors.RESET
    return result


ASCII_ART = """▄▄▄██▀▀▀██████   █████▒▓█████▄▄▄█████▓ ▄████▄   ██░ ██
   ▒██ ▒██    ▒ ▓██   ▒ ▓█   ▀▓  ██▒ ▓▒▒██▀ ▀█  ▓██░ ██▒
   ░██ ░ ▓██▄   ▒████ ░ ▒███  ▒ ▓██░ ▒░▒▓█    ▄ ▒██▀▀██░
▓██▄██▓  ▒   ██▒░▓█▒  ░ ▒▓█  ▄░ ▓██▓ ░ ▒▓▓▄ ▄██▒░▓█ ░██
 ▓███▒ ▒██████▒▒░▒█░    ░▒████▒ ▒██▒ ░ ▒ ▓███▀ ░░▓█▒░██▓
 ▒▓▒▒░ ▒ ▒▓▒ ▒ ░ ▒ ░    ░░ ▒░ ░ ▒ ░░   ░ ░▒ ▒  ░ ▒ ░░▒░▒
 ▒ ░▒░ ░ ░▒  ░ ░ ░       ░ ░  ░   ░      ░  ▒    ▒ ░▒░ ░
 ░ ░ ░ ░  ░  ░   ░ ░       ░    ░      ░         ░  ░░ ░
 ░   ░       ░             ░  ░        ░ ░       ░  ░  ░
                                       ░"""


def ascii_art_animation():
    """Display embedded ASCII art with animation effect (Red Black Gradient)."""
    lines = ASCII_ART.strip().split("\n")
    for line in lines:
        print(gradient_text(line, "FF0000", "000000"))
        sys.stdout.flush()
        time.sleep(0.05)


def ensure_requirements():
    """Check requirements and install them automatically if missing."""
    print(f"{bcolors.RED}[*]{bcolors.RESET} Checking requirements...")
    # Silence noisy SSL warnings from verify=False fetches
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass
    missing = []
    try:
        import requests  # noqa: F401
    except ImportError:
        missing.append("requests")

    if not missing:
        print(f"{bcolors.RED}[+]{bcolors.RESET} All requirements satisfied.\n")
        return

    print(f"{bcolors.RED}[!]{bcolors.RESET} Missing: {', '.join(missing)} - installing automatically...")
    for pkg in missing:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--break-system-packages", pkg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                print(f"{bcolors.RED}[ERROR]{bcolors.RESET} Could not install {pkg}: {e}")
                print(f"{bcolors.RED}[INFO]{bcolors.RESET} Run manually: pip3 install {pkg}")
                sys.exit(1)
    print(f"{bcolors.RED}[+]{bcolors.RESET} Requirements installed.\n")


def is_js_url(entry):
    """True if entry looks like a JS file (ignores ?query and #fragment).

    Examples that must PASS:
      https://www.googletagmanager.com/gtm.js?id=GTM-KV28SC4J
      https://site.com/app.js?ver=4.3.1
      /tmp/test.js
    Examples that must SKIP:
      https://site.com/wp-json/oembed/1.0/embed?url=...
      https://site.com/wp-json/
      https://site.com/style.min.css
    """
    e = entry.strip()
    if not e:
        return False
    parsed = urlparse(e)
    # Remote URL
    if parsed.scheme in ("http", "https"):
        path = parsed.path.lower()
        return path.endswith(".js")
    
    clean = e.split("?")[0].split("#")[0].lower()
    return clean.endswith(".js")


def fetch_content(entry, timeout=15):
    """Fetch JS content from remote URL or local file. Returns (content, error)."""
    parsed = urlparse(entry.strip())
    if parsed.scheme in ("http", "https"):
        # Remote URL -> HTTP GET
        try:
            import requests
        except ImportError:
            return None, "requests module not installed"
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) jsfetch/1.0 By MuZaN"
            }
            r = requests.get(entry.strip(), headers=headers, timeout=timeout, verify=False)
            if r.status_code != 200:
                return None, f"HTTP {r.status_code}"
            ctype = r.headers.get("Content-Type", "")
            text = r.text
           
            if "html" in ctype.lower() and "<html" in text[:2000].lower() and ".js" not in text[:2000].lower():
                pass
            return text, None
        except Exception as e:
            return None, str(e)
    else:
       
        clean = entry.strip().split("?")[0].split("#")[0]
        try:
            with open(clean, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(), None
        except Exception as e:
            return None, str(e)


DUMMY_VALUES = {
    "", "null", "undefined", "none", "test", "testing", "example",
    "changeme", "xxx", "***", "123", "password", "your_api_key",
    "your-api-key", "yourapikey", "api_key", "your_token", "placeholder",
    "false", "true",
}


def is_dummy(value):
    v = value.strip().strip('"').strip("'").lower()
    if v in DUMMY_VALUES:
        return True
    if v.startswith("your_") or v.startswith("test_") or v.startswith("example"):
        return True
    if set(v) in ({"*"}, {"x"}, {"-"}) :
        return True
    return False


def scan_javascript(content, filename):
    """Smart scan: keyword -> value extraction + high-confidence provider patterns."""
    findings = []

   
    provider_patterns = [
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        (r'AIZA[0-9A-Za-z\-_]{35}', "Google API key"),
        (r'AIza[0-9A-Za-z\-_]{35}', "Google API key"),
        (r'xox[baprs]-[a-zA-Z0-9\-]{10,}', "Slack token"),
        (r'ghp_[a-zA-Z0-9]{36,}', "GitHub token"),
        (r'gho_[a-zA-Z0-9]{36,}', "GitHub OAuth token"),
        (r'sk-live-[a-zA-Z0-9]{16,}', "Stripe live key"),
        (r'rk-live-[a-zA-Z0-9]{16,}', "Stripe restricted key"),
        (r'sk-[a-zA-Z0-9]{20,}', "OpenAI/Secret key"),
        (r'ya29\.[a-zA-Z0-9\-_\.]{20,}', "Google OAuth token"),
        (r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_\.=]*', "JWT token"),
        (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "Private key block"),
    ]
    for pattern, desc in provider_patterns:
        for match in re.findall(pattern, content):
            if isinstance(match, tuple):
                match = match[0] if match else ""
            if not match or is_dummy(match):
                continue
            findings.append(f"{bcolors.RED}[API_KEY]{bcolors.RESET} {desc}: {match} (file: {filename})")

  
    smart_keywords = {
        
        "api_key": "API_KEY", "apikey": "API_KEY", "api-key": "API_KEY",
        "apiKey": "API_KEY", "app_key": "API_KEY", "appkey": "API_KEY",
        "public_key": "API_KEY", "publishable_key": "API_KEY",
        # secrets
        "client_secret": "SECRET", "clientSecret": "SECRET",
        "secret_key": "SECRET", "secretKey": "SECRET",
        "private_key": "SECRET", "privateKey": "SECRET",
        "aws_secret": "SECRET", "app_secret": "SECRET",
        # tokens
        "auth_token": "TOKEN", "authtoken": "TOKEN", "auth-token": "TOKEN",
        "authToken": "TOKEN", "access_token": "TOKEN", "accessToken": "TOKEN",
        "refresh_token": "TOKEN", "refreshToken": "TOKEN",
        "id_token": "TOKEN", "bearer": "TOKEN",
        "session_token": "TOKEN", "csrf_token": "TOKEN",
        # creds
        "password": "CRED", "passwd": "CRED", "pwd": "CRED",
        "username": "CRED", "login": "CRED",
    }

    seen_values = set()
    for keyword, label in smart_keywords.items():
        kw = re.escape(keyword)
        patterns = [
            rf'["\']?{kw}["\']?\s*:\s*["\']([^"\'\s;,<>}}]{{4,}})["\']',
            rf'["\']?{kw}["\']?\s*=\s*["\']?([^"\'\s;,<>}}]{{4,}})["\']?',
        ]
        for pat in patterns:
            for match in re.findall(pat, content, re.IGNORECASE):
                if isinstance(match, tuple):
                    match = match[0] if match else ""
                value = match.strip().strip(',').strip(';')
                if not value or is_dummy(value) or len(value) < 4:
                    continue
                
                if value in ("true", "false", "null", "undefined"):
                    continue
                if value.lower() in seen_values:
                    continue
                seen_values.add(value.lower())
                findings.append(
                    f"{bcolors.RED}[{label}]{bcolors.RESET} {keyword}: {value} (file: {filename})"
                )

   
    for match in re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content):
        if is_dummy(match):
            continue
        findings.append(f"{bcolors.RED}[CRED]{bcolors.RESET} Email: {match} (file: {filename})")

  
    url_pattern = r'(https?://[^\s<>"\'`]+)'
    for match in re.findall(url_pattern, content):
        parsed = urlparse(match)
        if parsed.netloc:
            findings.append(f"{bcolors.RED}[URL]{bcolors.RESET} Endpoint: {match} (file: {filename})")

    
    seen = set()
    uniq = []
    for f in findings:
        if f not in seen:
            seen.add(f)
            uniq.append(f)
    return uniq


def main():
    
    ascii_art_animation()
    print(f"{bcolors.RED}By MuZaN{bcolors.RESET}\n")

    
    ensure_requirements()

    parser = argparse.ArgumentParser(
        description="JS Fetch - JavaScript URL security scanner",
        epilog="By MuZaN",
    )
    parser.add_argument("-f", "--file", required=True, help="File containing JavaScript URLs")
    parser.add_argument("-o", "--output", required=True, help="Output file for findings")
    args = parser.parse_args()

    input_file = args.file
    output_file = args.output

    if not os.path.exists(input_file):
        print(f"{bcolors.RED}[ERROR]{bcolors.RESET} Input file not found: {input_file}")
        sys.exit(1)

    print(f"\n{bcolors.RED}[JS FETCH]{bcolors.RESET} Scanning JavaScript files...")
    print(f"Input: {input_file}")
    print(f"Output: {output_file}\n")

    print(f"{gradient_text('JS FETCH - JS SECURITY SCANNER', 'FF0000', '000000')}\n")

    try:
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"{bcolors.RED}[ERROR]{bcolors.RESET} Could not read input file: {e}")
        sys.exit(1)

    with open(output_file, "w", encoding="utf-8") as out:
        for raw in lines:
            entry = raw.strip().strip('"').strip("'")
            if not entry:
                continue

            
            if not is_js_url(entry):
                print(f"[SKIP] Not a JS file: {entry}")
                continue

            print(f"{bcolors.RED}[FETCH]{bcolors.RESET} {entry}")
            content, err = fetch_content(entry)
            if content is None:
                print(f"[SKIP] Could not fetch: {entry} ({err})")
                continue

            findings = scan_javascript(content, entry)
            if not findings:
                print(f"{bcolors.RED}[OK]{bcolors.RESET} No secrets found: {entry}")
            for finding in findings:
                print(finding)
                
                clean = re.sub(r'\x1b\[[0-9;]+m', '', finding)
                out.write(clean + "\n")

    print(f"\n{bcolors.RED}Results saved to: {output_file}{bcolors.RESET}")

   
    print(f"\n{bcolors.RED}By MuZaN{bcolors.RESET}\n")


if __name__ == "__main__":
    main()

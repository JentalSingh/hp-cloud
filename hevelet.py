#!/usr/bin/env python
# coding: utf-8

"""
HP Community – Full Sign‑up with Selenium Wire + Proxy Rotation + Cloudflare/Turnstile Solver
- Uses Selenium Wire (proxy auth support)
- Rotates proxies from proxies.txt
- Detects Cloudflare "Just a moment..." challenge
- Refreshes up to 2 times, then solves Turnstile via 2Captcha if needed
- Robust verification with SSO redirect detection and cookie debug
- Prints email & password on success
"""

import json
import os
import random
import re
import time
import traceback
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import requests
from seleniumwire import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException,
    NoSuchElementException,
    JavascriptException,
    WebDriverException,
    StaleElementReferenceException,
    ElementClickInterceptedException,
)
from dotenv import load_dotenv
from faker import Faker

# Optional: Uncomment if you want auto chrome driver management
# from webdriver_manager.chrome import ChromeDriverManager
# from selenium.webdriver.chrome.service import Service

load_dotenv()

# ============================================================
# CONFIGURATION
# ============================================================
TARGET_URL = "https://h30434.www3.hp.com/t5/Printer-Wireless-Networking-Internet/Printer-not-connecting-to-wifi/td-p/9529101"
PROXY_FILE = Path("proxies.txt")
REGISTRATION_EMAIL = "sibenij593@joystill.com"   # CHANGE THIS
TWO_CAPTCHA_API_KEY = os.getenv("TWO_CAPTCHA_API_KEY", "")
PAGE_LOAD_WAIT = 10

if TWO_CAPTCHA_API_KEY and len(TWO_CAPTCHA_API_KEY) == 32:
    print(f"🔑 2Captcha API Key loaded: {TWO_CAPTCHA_API_KEY[:4]}...{TWO_CAPTCHA_API_KEY[-4:]}")
else:
    print("⚠️ 2Captcha API Key is missing or invalid – Turnstile solving will fail.")

# ============================================================
# TURNSTILE INTERCEPT SCRIPT (CDP)
# ============================================================
TURNSTILE_INTERCEPT_SCRIPT = """
(() => {
  if (window.__tsInterceptorInstalled) return;
  window.__tsInterceptorInstalled = true;
  window.__tsParams = null;
  window.__tsCallback = null;
  console.clear = () => console.log("Console was cleared");
  const patch = () => {
    if (!window.turnstile || typeof window.turnstile.render !== "function" || window.turnstile.__codexPatched) return false;
    const originalRender = window.turnstile.render.bind(window.turnstile);
    window.turnstile.render = (container, options = {}) => {
      window.__tsParams = {
        sitekey: options.sitekey || null,
        pageurl: window.location.href,
        data: options.cData || null,
        pagedata: options.chlPageData || null,
        action: options.action || null,
        userAgent: navigator.userAgent,
        json: 1
      };
      window.cfCallback = typeof options.callback === "function" ? options.callback : null;
      console.log("intercepted-params:" + JSON.stringify(window.__tsParams));
      return originalRender(container, options);
    };
    window.turnstile.__codexPatched = true;
    return true;
  };
  const timer = setInterval(() => { if (patch()) clearInterval(timer); }, 50);
  setTimeout(() => clearInterval(timer), 20000);
})();
"""

# ============================================================
# PROXY LOADING & PARSING
# ============================================================
def load_proxies():
    proxies = []
    if PROXY_FILE.exists():
        with PROXY_FILE.open("r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    proxies.append(line)
    return proxies

def build_proxy_config(proxy_value):
    if not proxy_value:
        return None
    if "://" not in proxy_value and ":" in proxy_value:
        parts = proxy_value.split(":")
        if len(parts) == 2:
            host, port = parts
            return {"host": host, "port": int(port), "username": "", "password": "", "label": f"{host}:{port}"}
        elif len(parts) == 4:
            host, port, username, password = parts
            return {"host": host, "port": int(port), "username": username, "password": password, "label": f"{host}:{port}"}
    parsed = urlparse(proxy_value if "://" in proxy_value else f"http://{proxy_value}")
    if not parsed.hostname or not parsed.port:
        return None
    return {
        "host": parsed.hostname,
        "port": parsed.port,
        "username": parsed.username or "",
        "password": parsed.password or "",
        "label": f"{parsed.hostname}:{parsed.port}",
    }

def get_proxy_candidates(limit=20):
    proxies = load_proxies()
    if not proxies:
        print("⚠️ No proxies found – using direct connection.")
        return [None]
    random.shuffle(proxies)
    candidates = []
    for p in proxies[:limit]:
        cfg = build_proxy_config(p)
        if cfg:
            candidates.append(cfg)
    if not candidates:
        candidates = [None]
    return candidates

# ============================================================
# DRIVER CREATION (Selenium Wire)
# ============================================================
def create_driver(proxy_config):
    chrome_options = webdriver.ChromeOptions()
    chrome_options.page_load_strategy = "none"
    chrome_options.add_argument("--no-first-run")
    chrome_options.add_argument("--no-default-browser-check")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument("--disable-infobars")
    chrome_options.add_argument("--start-maximized")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option("useAutomationExtension", False)
    
    # Enable browser console logging for intercept
    chrome_options.set_capability("goog:loggingPrefs", {"browser": "ALL"})

    # ---- Selenium Wire proxy configuration ----
    seleniumwire_options = {}
    if proxy_config:
        host = proxy_config["host"]
        port = proxy_config["port"]
        username = proxy_config.get("username")
        password = proxy_config.get("password")
        proxy_url = f"http://{host}:{port}"
        if username and password:
            proxy_url = f"http://{username}:{password}@{host}:{port}"
        elif username:
            proxy_url = f"http://{username}@{host}:{port}"
        seleniumwire_options = {
            "proxy": {
                "http": proxy_url,
                "https": proxy_url,
                "no_proxy": "localhost,127.0.0.1"
            },
            "verify_ssl": False,
        }
        print(f"✅ Proxy configured: {host}:{port}")

    # Create driver
    # If using webdriver_manager, uncomment below and comment the plain one
    # service = Service(ChromeDriverManager().install())
    # driver = webdriver.Chrome(service=service, options=chrome_options, seleniumwire_options=seleniumwire_options)
    driver = webdriver.Chrome(
        options=chrome_options,
        seleniumwire_options=seleniumwire_options
    )
    driver.implicitly_wait(10)
    driver.set_page_load_timeout(30)

    # Inject Turnstile intercept script (CDP)
    driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": TURNSTILE_INTERCEPT_SCRIPT})
    
    return driver

# ============================================================
# IP CHECKER
# ============================================================
def check_browser_ip(driver):
    print("🌐 Checking browser public IP...")
    try:
        driver.get("https://api.ipify.org?format=json")
        time.sleep(2)
        body = driver.find_element(By.TAG_NAME, "body").text.strip()
        data = json.loads(body)
        ip = data.get("ip", "unknown")
        print(f"🌐 Browser public IP: {ip}")
        return ip
    except Exception as e:
        print(f"⚠️ IP check failed: {e}")
        return None
    finally:
        driver.get("about:blank")
        time.sleep(1)

# ============================================================
# CLOUDFLARE CHALLENGE DETECTION & SOLVER (Selenium Version)
# ============================================================
def is_cloudflare_challenge(driver):
    try:
        title = (driver.title or "").lower()
    except:
        title = ""
    try:
        body = driver.find_element(By.TAG_NAME, "body").text.lower()
    except:
        body = ""
    
    markers = [
        "just a moment",
        "performing security verification",
        "checking your browser",
        "verify you are human",
        "this website uses a security service",
        "ray id:",
        "performance and security by cloudflare",
    ]
    return any(m in title for m in markers) or any(m in body for m in markers)

def drain_browser_logs(driver):
    intercepted = None
    try:
        entries = driver.get_log("browser")
    except Exception:
        return None
    for entry in entries:
        message = entry.get("message", "")
        if "intercepted-params:" in message:
            try:
                log_entry = message.encode("utf-8").decode("unicode_escape")
            except Exception:
                log_entry = message
            match = re.search(r'intercepted-params:({.*?})', log_entry)
            if match:
                try:
                    intercepted = json.loads(match.group(1))
                except json.JSONDecodeError:
                    pass
        if "turnstile" in message.lower() or "cloudflare" in message.lower() or "403" in message:
            print("Browser console:", message)
    return intercepted

def extract_turnstile_from_page(driver):
    try:
        params = driver.execute_script("return window.__tsParams;")
        if params and params.get("sitekey"):
            return params
    except (JavascriptException, WebDriverException):
        pass
    try:
        element = driver.find_element(By.CSS_SELECTOR, ".cf-turnstile,[data-sitekey]")
        sitekey = element.get_attribute("data-sitekey")
        if sitekey:
            return {
                "sitekey": sitekey,
                "pageurl": driver.current_url,
                "data": element.get_attribute("data-cdata"),
                "pagedata": None,
                "action": element.get_attribute("data-action"),
                "userAgent": driver.execute_script("return navigator.userAgent;"),
                "json": 1,
            }
    except Exception:
        pass
    try:
        iframes = driver.find_elements(By.CSS_SELECTOR, "iframe[src*='turnstile']")
    except Exception:
        iframes = []
    for iframe in iframes:
        src = iframe.get_attribute("src") or ""
        query = parse_qs(urlparse(src).query)
        sitekey = (query.get("sitekey") or query.get("k") or [None])[0]
        if sitekey:
            return {
                "sitekey": sitekey,
                "pageurl": driver.current_url,
                "data": None,
                "pagedata": None,
                "action": None,
                "userAgent": driver.execute_script("return navigator.userAgent;"),
                "json": 1,
            }
    return None

def wait_for_turnstile_params(driver, timeout_seconds=30):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        intercepted = drain_browser_logs(driver)
        if intercepted and intercepted.get("sitekey"):
            print("Captured Turnstile params from browser logs")
            return intercepted
        params = extract_turnstile_from_page(driver)
        if params and params.get("sitekey"):
            print("Captured Turnstile params from page state")
            return params
        time.sleep(1)
    return None

def solve_turnstile_2captcha(params):
    if not TWO_CAPTCHA_API_KEY or len(TWO_CAPTCHA_API_KEY) != 32:
        raise RuntimeError("TWO_CAPTCHA_API_KEY invalid")
    payload = {
        "key": TWO_CAPTCHA_API_KEY,
        "method": "turnstile",
        "sitekey": params["sitekey"],
        "pageurl": params["pageurl"],
        "json": 1,
    }
    if params.get("action"):
        payload["action"] = params["action"]
    if params.get("data"):
        payload["data"] = params["data"]
    if params.get("pagedata"):
        payload["pagedata"] = params["pagedata"]
    if params.get("userAgent"):
        payload["useragent"] = params["userAgent"]
    
    print(f"🔄 Submitting Turnstile to 2Captcha for {params['pageurl']}")
    response = requests.post("https://2captcha.com/in.php", data=payload, timeout=60)
    response.raise_for_status()
    data = response.json()
    if data.get("status") != 1:
        raise RuntimeError(f"2Captcha submit failed: {data}")
    captcha_id = data["request"]
    print(f"✅ 2Captcha accepted request id: {captcha_id}")
    
    for attempt in range(1, 31):
        time.sleep(5)
        poll = requests.get(
            "https://2captcha.com/res.php",
            params={"key": TWO_CAPTCHA_API_KEY, "action": "get", "id": captcha_id, "json": 1},
            timeout=60,
        )
        poll.raise_for_status()
        result = poll.json()
        if result.get("status") == 1:
            token = result.get("request")
            if token:
                print(f"✅ Received 2Captcha token on attempt {attempt}")
                return token
        elif result.get("request") == "CAPCHA_NOT_READY":
            print(f"⏳ 2Captcha still solving ({attempt}/30)")
        else:
            raise RuntimeError(f"2Captcha poll failed: {result}")
    raise TimeoutError("2Captcha timeout")

def apply_turnstile_token(driver, token):
    print("🔄 Applying Turnstile token")
    result = driver.execute_script(
        """
        const solveToken = arguments[0];
        if (typeof window.cfCallback === "function") {
            window.cfCallback(solveToken);
            return "callback";
        }
        let applied = false;
        document.querySelectorAll('input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]').forEach((el) => {
            el.value = solveToken;
            el.dispatchEvent(new Event("input", { bubbles: true }));
            el.dispatchEvent(new Event("change", { bubbles: true }));
            applied = true;
        });
        return applied ? "input" : "none";
        """,
        token,
    )
    print(f"✅ Applied Turnstile token via '{result}' mode")

def wait_for_challenge_clear(driver, timeout_seconds=20):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            current_url = driver.current_url
            title = (driver.title or "").strip().lower()
            page_source = (driver.page_source or "").lower()
        except:
            time.sleep(0.5)
            continue
        challenge_markers = (
            "__cf_chl_rt_tk=" in current_url
            or "just a moment" in title
            or "cf-challenge-running" in page_source
            or "challenge-form" in page_source
            or "why_captcha" in page_source
        )
        if not challenge_markers:
            print("✅ Challenge cleared.")
            return True
        time.sleep(1)
    print("❌ Challenge may not have cleared within timeout.")
    return False

def manual_captcha_wait():
    print("\n🔴 Please solve the CAPTCHA manually in the browser.")
    input("🟢 Press ENTER after solving...")
    print("✅ Continuing.")

def handle_cloudflare_challenge(driver):
    """
    Master function to handle Cloudflare:
    1. Refresh up to 2 times.
    2. If still present, solve with Turnstile + 2Captcha.
    3. Fallback to manual wait.
    """
    # Check if challenge is present
    if not is_cloudflare_challenge(driver):
        print("✅ No Cloudflare challenge detected initially.")
        return True
    
    print("🛡️ Cloudflare challenge page detected.")
    
    # Attempt 1: Refresh up to 2 times
    MAX_CF_REFRESHES = 2
    for refresh_attempt in range(MAX_CF_REFRESHES + 1):
        if not is_cloudflare_challenge(driver):
            print("✅ Cloudflare challenge cleared after refresh.")
            return True
        if refresh_attempt >= MAX_CF_REFRESHES:
            print("❌ Cloudflare challenge still active after refresh retries.")
            break
        print(f"🔄 Refreshing page ({refresh_attempt + 1}/{MAX_CF_REFRESHES})...")
        driver.refresh()
        try:
            WebDriverWait(driver, 15).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
        except Exception:
            pass
        time.sleep(3)
    
    # Attempt 2: Automated solving
    if is_cloudflare_challenge(driver):
        print("🛡️ Attempting to solve with Turnstile + 2Captcha...")
        params = wait_for_turnstile_params(driver, timeout_seconds=30)
        if params:
            print("✅ Turnstile params captured. Solving with 2Captcha...")
            try:
                token = solve_turnstile_2captcha(params)
                apply_turnstile_token(driver, token)
                if wait_for_challenge_clear(driver, timeout_seconds=30):
                    print("✅ Challenge cleared after solving.")
                    time.sleep(3)
                    return True
                else:
                    print("❌ Challenge did not clear after applying token.")
                    manual_captcha_wait()
                    if not is_cloudflare_challenge(driver):
                        print("✅ Manual intervention cleared the challenge.")
                        return True
                    else:
                        return False
            except Exception as e:
                print(f"⚠️ Turnstile solving failed: {e}")
                traceback.print_exc()
        else:
            print("ℹ️ No Turnstile params found.")
    
    # Attempt 3: Manual fallback
    print("⚠️ Automated solving failed or unavailable. Falling back to manual...")
    manual_captcha_wait()
    if not is_cloudflare_challenge(driver):
        print("✅ Manual intervention cleared the challenge.")
        return True
    else:
        print("❌ Challenge still present after manual wait.")
        return False

# ============================================================
# HP-SPECIFIC ACTIONS (Selenium)
# ============================================================
def click_login_or_signup(driver):
    print("🔘 Looking for 'Sign in / Create an account'...")
    selectors = [
        "//a[contains(text(), 'Sign in / Create an account')]",
        "//a[contains(text(), 'Sign in')]",
        "//a[contains(@href, 'oauth2sso_v2/sso_login_redirect')]",
        "//a[contains(text(), 'Sign up / Sign in')]",
    ]
    for selector in selectors:
        try:
            elements = driver.find_elements(By.XPATH, selector)
            for el in elements:
                if el.is_displayed() and el.is_enabled():
                    print(f"✅ Found: {selector}")
                    driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
                    time.sleep(0.5)
                    try:
                        el.click()
                    except:
                        driver.execute_script("arguments[0].click();", el)
                    print("✅ Clicked 'Sign in / Create an account'")
                    time.sleep(3)
                    return True
        except Exception as e:
            print(f"⚠️ Selector failed: {selector} - {e}")
    print("❌ Could not find 'Sign in / Create an account'.")
    driver.save_screenshot("hp_signin_not_found.png")
    return False

def wait_and_click_create_account(driver):
    print("⏳ Waiting for 'Create account' on login page...")
    selectors = [
        "//a[contains(text(), 'Create account')]",
        "//button[contains(text(), 'Create account')]",
    ]
    for selector in selectors:
        try:
            element = WebDriverWait(driver, 20).until(
                EC.element_to_be_clickable((By.XPATH, selector))
            )
            print(f"✅ Found: {selector}")
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", element)
            time.sleep(0.5)
            try:
                element.click()
            except:
                driver.execute_script("arguments[0].click();", element)
            print("✅ 'Create account' clicked.")
            time.sleep(3)
            return True
        except Exception as e:
            print(f"⚠️ {selector} not clickable: {e}")
    print("❌ Could not click 'Create account'.")
    driver.save_screenshot("hp_create_account_not_found.png")
    return False

def fill_signup_form(driver, first_name, last_name, email, password):
    print("✍️ Filling sign-up form...")
    fields = {
        "firstName": first_name,
        "lastName": last_name,
        "email": email,
        "password": password,
    }
    for field_id, value in fields.items():
        try:
            el = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.ID, field_id))
            )
            el.clear()
            el.send_keys(value)
            print(f"   ✅ Filled {field_id}")
        except Exception as e:
            print(f"   ❌ Could not fill {field_id}: {e}")
            driver.save_screenshot(f"hp_field_{field_id}_error.png")
            return False
    return True

def check_terms_checkbox(driver):
    print("🔘 Looking for terms checkbox...")
    try:
        checkbox = driver.find_element(By.CSS_SELECTOR, "input[type='checkbox']")
        if checkbox.is_displayed() and not checkbox.is_selected():
            driver.execute_script("arguments[0].click();", checkbox)
            print("✅ Checkbox checked.")
            return True
        elif checkbox.is_selected():
            print("✅ Checkbox already checked.")
            return True
    except Exception:
        pass
    try:
        span = driver.find_element(By.CSS_SELECTOR, "span.vn-checkbox__span")
        if span.is_displayed():
            driver.execute_script("arguments[0].click();", span)
            print("✅ Checkbox clicked via span.")
            return True
    except:
        pass
    print("⚠️ Checkbox not found or not needed.")
    return False

def click_create_button(driver):
    print("🔘 Looking for Create button...")
    selectors = [
        "//button[contains(text(), 'Create')]",
        "//button[@type='submit']",
        "//button[contains(@class, 'css-1q5f153')]",
    ]
    for selector in selectors:
        try:
            element = driver.find_element(By.XPATH, selector)
            if element.is_displayed() and element.is_enabled():
                driver.execute_script("arguments[0].scrollIntoView({block:'center'});", element)
                time.sleep(0.5)
                try:
                    element.click()
                except:
                    driver.execute_script("arguments[0].click();", element)
                print("✅ Create button clicked.")
                return True
        except Exception as e:
            print(f"⚠️ {selector} failed: {e}")
    print("❌ Could not click Create button.")
    driver.save_screenshot("hp_create_button_error.png")
    return False

# ============================================================
# VERIFICATION & LOGIN CONFIRMATION (UPDATED WITH REDIRECT WAIT)
# ============================================================

def confirm_logged_in(driver):
    """Check for Lithium auth cookies and UI state with detailed logging."""
    cookies = driver.get_cookies()
    cookie_names = {c["name"] for c in cookies}
    has_session_cookie = "LithiumUserSecure" in cookie_names and "LithiumUserInfo" in cookie_names

    print("\n🔍 Checking Lithium cookies:")
    for c in cookies:
        if c["name"] in ("LithiumUserInfo", "LithiumUserSecure"):
            print(f"   ✅ {c['name']} domain={c.get('domain')} path={c.get('path')} secure={c.get('secure')} httpOnly={c.get('httpOnly')}")

    if has_session_cookie:
        print("✅ HP authentication cookies detected.")
    else:
        print("❌ HP authentication cookies NOT detected.")

    try:
        body = driver.find_element(By.TAG_NAME, "body").text
        if "Sign in / Create an account" not in body and "Sign up / Sign in" not in body:
            print("✅ UI shows logged-in state (no anonymous sign-in links).")
            return True
    except:
        pass

    return has_session_cookie

def verify_and_login(driver, verification_link):
    """Open verification link, wait for SSO redirect, confirm login with full cookie debug."""
    if not verification_link:
        return False

    print("\n🌐 Opening verification link...")
    driver.get(verification_link)
    time.sleep(3)

    # ---- Wait for redirect to community domain ----
    print("⏳ Waiting for SSO redirect to HP Community (max 30s)...")
    redirect_occurred = False
    for i in range(30):
        current_url = driver.current_url
        print(f"{i:02d}  {current_url}")
        if "h30434" in current_url or "www3.hp.com" in current_url:
            print("✅ SSO redirect completed.")
            redirect_occurred = True
            break
        time.sleep(1)

    # ---- If no redirect, try to find a continue button ----
    if not redirect_occurred:
        print("⚠️ Auto-redirect not detected. Looking for 'Continue' or 'Return to community' button...")
        try:
            continue_btn = driver.find_element(By.XPATH, "//a[contains(text(), 'Continue')] | //a[contains(text(), 'Return')] | //button[contains(text(), 'Continue')]")
            if continue_btn.is_displayed():
                driver.execute_script("arguments[0].click();", continue_btn)
                print("✅ Clicked 'Continue' button.")
                time.sleep(5)
                # Check again for redirect
                for i in range(10):
                    current_url = driver.current_url
                    print(f"Post-click {i:02d}  {current_url}")
                    if "h30434" in current_url or "www3.hp.com" in current_url:
                        print("✅ SSO redirect completed after clicking continue.")
                        redirect_occurred = True
                        break
                    time.sleep(1)
        except:
            print("ℹ️ No continue button found.")
        
        # If still no redirect, fallback to manual navigation
        if not redirect_occurred:
            print("⚠️ Redirect still not happened. Navigating to community page manually...")
            driver.get("https://h30434.www3.hp.com/")
            time.sleep(5)
            if "h30434" in driver.current_url:
                print("✅ Manual navigation to community page successful.")
                redirect_occurred = True

    # ---- Wait for cookies to settle ----
    if redirect_occurred:
        print("⏳ Waiting 5 seconds for cookies to settle...")
        time.sleep(5)
    else:
        print("❌ Could not reach community page. Aborting verification.")
        return False

    # ---- Print all cookies for debugging ----
    print("\n========== ALL COOKIES AFTER VERIFICATION ==========")
    all_cookies = driver.get_cookies()
    for c in all_cookies:
        domain = c.get('domain', 'N/A')
        name = c.get('name', 'N/A')
        value = c.get('value', 'N/A')[:20] + "..." if len(c.get('value', '')) > 20 else c.get('value', '')
        print(f"  {name}  domain={domain}  value={value}")
    print("====================================================\n")

    # ---- Final login check ----
    if confirm_logged_in(driver):
        print("🎉 LOGIN CONFIRMED SUCCESSFULLY!")
        driver.save_screenshot("hp_final_login_success.png")
        return True
    else:
        print("❌ Login could not be confirmed.")
        driver.save_screenshot("hp_final_login_failed.png")
        return False

# ============================================================
# USER DATA GENERATION
# ============================================================
def generate_user_data():
    fake = Faker()
    first_name = fake.first_name()
    last_name = fake.last_name()
    password = fake.password(length=12, special_chars=True, digits=True, upper_case=True, lower_case=True)
    return {
        "first_name": first_name,
        "last_name": last_name,
        "password": password,
    }

# ============================================================
# MAIN AUTOMATION
# ============================================================
def run_automation(proxy_config):
    driver = create_driver(proxy_config)
    try:
        # ---- CHECK BROWSER IP ----
        check_browser_ip(driver)
        
        # Generate user
        user = generate_user_data()
        first_name = user["first_name"]
        last_name = user["last_name"]
        email = REGISTRATION_EMAIL
        password = user["password"]
        
        print("\n🧑 Generated user data:")
        print(f"   First Name: {first_name}")
        print(f"   Last Name: {last_name}")
        print(f"   Email: {email}")
        print(f"   Password: {password}")
        
        # ---- OPEN TARGET URL ----
        print(f"\n🌐 Opening page: {TARGET_URL}")
        driver.get(TARGET_URL)
        time.sleep(5)
        
        # ---- HANDLE CLOUDFLARE CHALLENGE ----
        if not handle_cloudflare_challenge(driver):
            print("❌ Cloudflare challenge could not be resolved. Aborting.")
            driver.save_screenshot("hp_cloudflare_failed.png")
            return False
        
        # ---- VERIFY HP PAGE ----
        print(f"⏳ Waiting {PAGE_LOAD_WAIT} seconds for page to settle...")
        time.sleep(PAGE_LOAD_WAIT)
        
        # Check if actual HP page
        try:
            body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
            if "hp support community" not in driver.title.lower() or "printer not connecting to wifi" not in body_text:
                print("⚠️ HP content not detected.")
                driver.save_screenshot("hp_content_not_detected.png")
                return False
        except:
            pass
        print("✅ HP page loaded successfully.")
        
        # ---- COOKIE CONSENT ----
        print("🍪 Accepting cookies...")
        try:
            accept_btns = driver.find_elements(By.XPATH, "//button[contains(text(), 'Accept All')]")
            if accept_btns and accept_btns[0].is_displayed():
                accept_btns[0].click()
                print("✅ Cookies accepted.")
                time.sleep(2)
        except:
            print("ℹ️ No cookie banner.")
        
        # ---- 1. CLICK SIGN IN / CREATE ACCOUNT ----
        if not click_login_or_signup(driver):
            return False
        
        # ---- 2. WAIT FOR LOGIN PAGE AND CLICK CREATE ACCOUNT ----
        print("⏳ Waiting for HP login page...")
        try:
            WebDriverWait(driver, 20).until(
                lambda d: "login3.id.hp.com" in d.current_url or "sso_login" in d.current_url
            )
            print(f"✅ Login page loaded: {driver.current_url}")
        except:
            print("⚠️ URL did not match, but continuing...")
        
        if not wait_and_click_create_account(driver):
            return False
        
        # ---- 3. FILL SIGNUP FORM ----
        if not fill_signup_form(driver, first_name, last_name, email, password):
            return False
        
        # ---- 4. TERMS CHECKBOX ----
        check_terms_checkbox(driver)
        
        # ---- 5. CLICK CREATE BUTTON ----
        if not click_create_button(driver):
            return False
        
        # ---- 6. WAIT FOR SUBMISSION ----
        time.sleep(5)
        driver.save_screenshot("hp_signup_submitted.png")
        print("📸 Screenshot saved: hp_signup_submitted.png")
        
        # ---- 7. VERIFICATION LINK ----
        print("\n" + "="*60)
        print("📧 Verification email sent. Please paste the verification link:")
        verification_link = input("🔗 Paste link: ").strip()
        if not verification_link:
            print("❌ No link provided. Exiting.")
            return False
        
        # ---- 8. VERIFY AND LOGIN (UPDATED) ----
        login_ok = verify_and_login(driver, verification_link)
        
        if login_ok:
            print("\n" + "="*60)
            print("🎉 SIGN-UP AND LOGIN COMPLETED SUCCESSFULLY!")
            print("="*60)
            print(f"📧 Email    : {email}")
            print(f"🔑 Password : {password}")
            print("="*60)
            return True
        else:
            print("❌ Login could not be confirmed.")
            return False
            
    except Exception as e:
        print(f"❌ Automation failed: {e}")
        traceback.print_exc()
        driver.save_screenshot("hp_error_screenshot.png")
        return False
    finally:
        input("\n⏸️ Press ENTER to close browser...")
        driver.quit()

# ============================================================
# MAIN LOOP – PROXY ROTATION
# ============================================================
def main():
    print("\n" + "="*70)
    print("🚀 HP SIGN-UP WITH SELENIUM + PROXY ROTATION + CLOUDFLARE SOLVER")
    print("="*70)
    print(f"📧 Using email: {REGISTRATION_EMAIL}")
    
    candidates = get_proxy_candidates(limit=20)
    for i, proxy_config in enumerate(candidates, 1):
        print(f"\n🔁 Attempt {i} using {proxy_config['label'] if proxy_config else 'Direct connection'}")
        success = run_automation(proxy_config)
        if success:
            print("\n✅ SUCCESS! Sign-up completed.")
            return
        else:
            print("\n❌ This attempt failed. Trying next proxy...")
    print("\n❌ All attempts failed.")

if __name__ == "__main__":
    main()
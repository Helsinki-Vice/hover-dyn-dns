import requests
import requests.cookies
import base64
import hmac
import hashlib
import struct
import time
import json
import os

from logging_out import log_output

AUTH_ENDPOINT = "https://www.hover.com/signin/auth.json"
AUTH_2FA_ENDPOINT = "https://www.hover.com/signin/auth2.json"
DOMAIN_CHECK_URL = "https://www.hover.com/api/domains"
COOKIES_FILE = "./cookies.json"


def generate_totp(secret: str, time_step:int=30, digits:int=6) -> str:
    """
    Generates a one-time passcode for TFA using the provided shared secret.
    """
    # Decode base32 secret
    secret = secret.upper()
    secret = secret.replace(' ','')
    missing_padding = len(secret) % 8
    if missing_padding:
        secret += '=' * (8 - missing_padding)
    key = base64.b32decode(secret, casefold=True)
    # Get current time step
    current_time = int(time.time() // time_step)
    # Pack time into byte array (big-endian)
    time_bytes = struct.pack(">Q", current_time)
    # Generate HMAC-SHA1
    hmac_result = hmac.new(key, time_bytes, hashlib.sha1).digest()
    # Extract dynamic binary code
    offset = hmac_result[-1] & 0x0F
    binary = struct.unpack(">I", hmac_result[offset:offset + 4])[0] & 0x7FFFFFFF
    # Compute TOTP value
    otp = binary % (10 ** digits)
    return f"{otp:0{digits}d}"

def init_session(proxies, logfile: str, logging: bool) -> requests.cookies.RequestsCookieJar:
    """
    Initializes a session with Hover to retrieve cookies.
    """
    response = requests.get("https://www.hover.com/signin", proxies=proxies, verify=True)
    log_output(f"Init session response status code: {response.status_code}", logfile, logging)
    return response.cookies


def submit_username_password(username: str, password: str, cookies: requests.cookies.RequestsCookieJar, proxies, logfile: str, logging: bool) -> requests.Response:
    """
    Logs in to Hover with the provided username and password.
    """
    login_payload = {
        "username": username,
        "password": password,
        "token": None
    }
    response = requests.post(AUTH_ENDPOINT, json=login_payload, proxies=proxies, verify=True, cookies=cookies)
    log_output(f"Payload: {login_payload}", logfile, logging)
    log_output(f"Login response status code: {response.status_code}", logfile, logging)
    log_output(f"Login response content: {response.content}", logfile, logging)
    log_output(f"Cookies: {cookies}", logfile, logging)
    return response


def submit_2fa_code(totp_code, cookies, proxies, logfile: str, logging: bool):
    """
    Performs 2FA login with the provided TOTP code.
    """
    login_payload = {
        "code": totp_code
    }
    response = requests.post(AUTH_2FA_ENDPOINT, json=login_payload, proxies=proxies, cookies=cookies, verify=True)
    log_output(f"Payload: {login_payload}", logfile, logging)
    log_output(f"Login 2FA response status code: {response.status_code}", logfile, logging)
    log_output(f"Login 2FA response content: {response.content}", logfile, logging)
    log_output(f"Cookies: {cookies}", logfile, logging)
    return response


def save_cookies(cookies):
    """
    Saves cookies to a JSON file.
    """
    with open(COOKIES_FILE, 'w') as file:
        json.dump(cookies.get_dict(), file)


def load_cookies(cookies_filename: str) -> requests.cookies.RequestsCookieJar | None:
    """
    Loads cookies from a JSON file.
    """
    if os.path.isfile(cookies_filename):
        with open(COOKIES_FILE, 'r') as file:
            cookies_dict = json.load(file)
            return requests.cookies.cookiejar_from_dict(cookies_dict)
    return None


def check_cookies_validity(cookies: requests.cookies.RequestsCookieJar | None, proxies):
    """
    Checks if the cookies are still valid by making a request to an authenticated endpoint.
    """
    if cookies is None:
        return False
    response = requests.get(DOMAIN_CHECK_URL, cookies=cookies, proxies=proxies, verify=True)
    return response.status_code == 200


def login(username: str, password: str, totp_secret: str, proxies, logfile: str, logging: bool) -> requests.cookies.RequestsCookieJar | None:

    log_output("Logging in to hover...", logfile, logging)
    # Check if we are logged in already, reuse session if so
    cookies = load_cookies(COOKIES_FILE)
    if check_cookies_validity(cookies, proxies):
        log_output("Skipping login process because we are already logged in.", logfile, logging)
        return cookies
    
    # Otherwise, log in from scratch
    cookies = init_session(proxies, logfile, logging)
    try:
        login_response = submit_username_password(username, password, cookies, proxies, logfile, logging)
        login_response_cookies = login_response.cookies
        login_response = login_response.json()
    except json.JSONDecodeError:
        log_output(f"Could not login: the endpoint {AUTH_ENDPOINT} did not return JSON data as expected.", logfile, logging)
        exit()
    
    if not isinstance(login_response, dict):
        log_output(f"Could not login: the endpoint {AUTH_ENDPOINT} returned {login_response} instead of valid JSON.", logfile, logging)
        exit()
    
    login_error = login_response.get("error")
    if login_error:
        log_output(f"Could not login: the endpoint {AUTH_ENDPOINT} returned the following error: {login_response}", logfile, logging)
        exit()
    
    if login_response.get("status") == "completed":
        cookies = login_response_cookies
    else:
        auth_type = login_response.get("type")
        if auth_type == "app":
            # We have submitted our username and password, time for the 2FA code
            totp = generate_totp(totp_secret)
            try:
                totp_response = submit_2fa_code(totp, cookies, proxies, logfile, logging)
                cookies = totp_response.cookies
                totp_response = totp_response.json()
            except json.JSONDecodeError:
                log_output(f"Could not submit 2fa login code: the endpoint {AUTH_2FA_ENDPOINT} did not return JSON data as expected.", logfile, logging)
                exit()

            if not isinstance(totp_response, dict):
                log_output(f"Could not login: the endpoint {AUTH_2FA_ENDPOINT} returned {totp_response} instead of valid JSON.", logfile, logging)
                exit()
            if totp_response.get("succeeded") != True:
                log_output(f"Could not login: totp code {totp} was not accepted. The server's response was was: {totp_response}", logfile, logging)
                exit()
        elif auth_type == None:
            pass
        else:
            log_output(f"Hover is asking for a 2FA type of '{auth_type}', which we cannot handle. In your account settings, disable 2FA and re-enable as app authentication. See the readme for more details.", logfile, logging)
            exit()

    # Logged in... in theory. Let's double check.
    if check_cookies_validity(cookies, proxies):
        log_output("Login success.", logfile, logging)
        save_cookies(cookies)
        return cookies
    else:
        log_output(f"The login process seemed to go well, but the server is not accepting our auth cookie of {cookies.get('hoverauth')}.", logfile, logging)
        exit()
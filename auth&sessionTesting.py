import requests
import re

DVWA_URL = "http://localhost:8080"
LOGIN_URL = DVWA_URL + "login.php"
PROFILE_URL = DVWA_URL + "index.php"
SECURITY_LEVEL = "low"

def get_csrf_token(session, login_url):
    resp = session.get(login_url)
    match = re.search(r'name="user_token" value="([^"]+)"', resp.text)
    if match:
        return match.group(1)
    raise Exception("CSRF token not found")

def dvwa_login(session, username, password, security_level):
    user_token = get_csrf_token(session, LOGIN_URL)
    cookies = {
        "security": security_level,
    }
    data = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": user_token,
    }
    resp = session.post(LOGIN_URL, data=data, cookies=cookies)
    if "Welcome to Damn Vulnerable Web Application" in resp.text:
        print("Login successful!")
        return resp.cookies
    else:
        print("Login failed.")
        return None

def check_cookie_flags(session):
    for cookie in session.cookies:
        print(f"{cookie.name}: Secure={cookie.secure}, HttpOnly={cookie._rest.get('HttpOnly', False)}")

def test_session_fixation(session, username, password, security_level):
    # Set a known PHPSESSID before login
    fixed_session_id = "fixedsessionid123"
    session.cookies.set("PHPSESSID", fixed_session_id, path="/", domain="127.0.0.1")
    dvwa_login(session, username, password, security_level)
    new_sessionid = session.cookies.get("PHPSESSID")
    if new_sessionid != fixed_session_id:
        print("Session ID rotated after login: Secure against Fixation")
    else:
        print("Session ID not rotated: Vulnerable to fixation")

def test_profile_access(session):
    resp = session.get(PROFILE_URL)
    if "Welcome to Damn Vulnerable Web Application" in resp.text:
        print("Authenticated access confirmed.")
    else:
        print("Profile access failed.")

if __name__ == "__main__":
    session = requests.Session()
    cookies = dvwa_login(session, "admin", "password", SECURITY_LEVEL)
    check_cookie_flags(session)
    test_session_fixation(session, "admin", "password", SECURITY_LEVEL)
    test_profile_access(session)

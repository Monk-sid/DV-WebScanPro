import re
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Base URL of target application
BASE_URL = "http://localhost:8080/"

# Login and profile URLs based on base URL
LOGIN_URL = urljoin(BASE_URL, "login.php")
PROFILE_URL = urljoin(BASE_URL, "index.php")

# Default HTTP headers
DEFAULT_HEADERS = {
    "User-Agent": "WebScanPro/1.0"
}

# SQL error regex patterns
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax;",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"odbc sql server driver",
    r"unknown column",
    r"sql syntax.*?mysql",
    r"mysql_fetch_assoc",
    r"mysql_num_rows",
    r"input string was not in a correct format",
]

def get_session():
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    return session

def is_same_domain(base, url):
    base_domain = urlparse(base).netloc.lower()
    check_domain = urlparse(url).netloc.lower()
    return base_domain == check_domain

def normalize_url(base, link):
    if not link:
        return None
    return urljoin(base, link)

def extract_links(html, base_url=BASE_URL):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all(['a', 'link', 'area']):
        href = tag.get("href")
        url = normalize_url(base_url, href)
        if url:
            links.add(url)
    for form in soup.find_all("form"):
        action = form.get("action")
        url = normalize_url(base_url, action)
        if url:
            links.add(url)
    return links

def extract_forms(html, base_url=BASE_URL):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        form_info = {
            "method": (form.get("method") or "get").lower(),
            "action": normalize_url(base_url, form.get("action")),
            "inputs": []
        }
        for input_tag in form.find_all(["input", "textarea", "select"]):
            input_info = {
                "name": input_tag.get("name"),
                "type": input_tag.get("type", "text"),
                "value": input_tag.get("value", ""),
            }
            form_info["inputs"].append(input_info)
        forms.append(form_info)
    return forms

def find_sql_errors(text):
    lowered_text = text.lower()
    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, lowered_text):
            return True, pattern
    return False, None

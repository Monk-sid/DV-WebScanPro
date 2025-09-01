import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


def get_session():
    """Returns a requests.Session with common headers."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; Crawler/1.0; +http://localhost/DVWA/)"
    })
    return session

def extract_links(html, base_url):
    """Extracts and returns a list of absolute links from HTML."""
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for a in soup.find_all("a", href=True):
        link = urljoin(base_url, a["href"].strip())
        links.append(link)
    return links

def extract_forms(html, page_url):
    """Extracts all forms and their details from HTML."""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        method = form.get("method", "get").lower()
        action = urljoin(page_url, form.get("action", ""))
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "type": inp.get("type", inp.name),
                "name": inp.get("name"),
                "value": inp.get("value", ""),
            })
        forms.append({
            "method": method,
            "action": action,
            "inputs": inputs
        })
    return forms

def normalize_url(url):
    """Standardizes URLs – removes trailing slashes, lowercases scheme/host."""
    url = url.strip()
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip('/')
    normalized = f"{scheme}://{netloc}{path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return normalized

def is_same_domain(base, url):
    """Returns True if url is in the same registered domain as base."""
    base_parsed = urlparse(base)
    url_parsed = urlparse(url)
    return base_parsed.netloc.lower() == url_parsed.netloc.lower()

def find_sql_errors(html):
    """Check response text for common SQL error messages."""
    errors = [
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "sqlstate"
    ]
    for err in errors:
        if err.lower() in html.lower():
            return True, err
    return False, None

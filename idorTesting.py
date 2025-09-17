import requests
import time

# Use DVWA default credentials
USERS = [
    {"username": "admin", "password": "password", "role": "admin"},
    {"username": "user", "password": "password", "role": "standard"},
]

# Correct DVWA endpoints
LOGIN_URL = "http://localhost:8080/login.php"  # DVWA login form endpoint
PROFILE_URL = "http://localhost:8080/vulnerabilities/idor/"  # IDOR page for horizontal tests
IDOR_TEST_URL = "http://localhost:8080/vulnerabilities/idor/"  # IDOR vulnerable URL

def login(session, username, password):
    login_data = {
        "username": username,
        "password": password
    }
    res = session.post(LOGIN_URL, data=login_data)  # use form-encoded data with 'data='
    # Consider testing for successful login here by checking res.text or cookies if needed
    return res.status_code == 200

def test_horizontal_escalation(session, user_id, target_user_id):
    # Simulate accessing another user's resource
    url = f"{PROFILE_URL}?id={target_user_id}"  # DVWA IDOR expects 'id' param in query string
    res = session.get(url)
    if res.status_code == 200 and target_user_id != user_id:
        print(f"Horizontal Privilege Escalation: User {user_id} accessed {target_user_id}'s data")
    else:
        print(f"Access denied or same user data requested.")

def test_vertical_escalation(session):
    # Attempt access to admin-only page, adjust URL to DVWA admin resource if exists 
    admin_url = "http://localhost:8080/admin.php"  # Example; replace with actual admin resource URL if any
    res = session.get(admin_url)
    if res.status_code == 200:
        print("Vertical Privilege Escalation: Accessed admin resource!")
    else:
        print("Access to admin resource denied.")

def test_idor(session, valid_id, test_id):
    # Access object by ID and test unauthorized access by modifying ID param
    url_valid = f"{IDOR_TEST_URL}?id={valid_id}"
    url_test = f"{IDOR_TEST_URL}?id={test_id}"

    res_valid = session.get(url_valid)
    res_test = session.get(url_test)

    if res_test.status_code == 200 and valid_id != test_id:
        print(f"IDOR Detected: Accessed object {test_id} unauthorized!")
    else:
        print("No IDOR detected or access denied.")

def main():
    findings = []
    for user_info in USERS:
        session = requests.Session()
        if login(session, user_info["username"], user_info["password"]):
            print(f"Logged in as {user_info['username']} (Role: {user_info['role']})")

            # Here user_id and target_user_id simulate user identifiers; DVWA does not expose user IDs, so use numeric IDs or strings as needed
            current_user_id = "1"  # example: current user id 1
            other_user_id = "2"    # example: another user id 2

            test_horizontal_escalation(session, current_user_id, other_user_id)
            test_vertical_escalation(session)
            test_idor(session, valid_id="1", test_id="2")
        else:
            print(f"Login failed for {user_info['username']}")

        time.sleep(0.3)  # Throttle between user tests

if __name__ == "__main__":
    main()

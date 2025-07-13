import requests
from requests.auth import HTTPBasicAuth

def check(ip, port=80):
    schemes = ['http', 'https'] if port in [443, 8443, 9443] else ['http']
    creds = [
        ('admin', 'admin'),
        ('admin', '12345'),
        ('admin', ''),
        ('root', 'root'),
    ]
    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}/cgi-bin/api.cgi"
        for user, pwd in creds:
            try:
                r = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=5, verify=False)
                if r.status_code == 200:
                    return True, f"Reolink default creds accepted: {user}:{pwd}"
            except Exception:
                continue
    return False, ""

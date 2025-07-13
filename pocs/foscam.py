import requests

def check(ip, port=80):
    schemes = ['http', 'https'] if port in [443, 8443, 9443] else ['http']
    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}/get_status.cgi"
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200 and "loginuse" in r.text:
                return True, "Foscam status endpoint accessible without auth"
        except Exception:
            continue
    return False, ""

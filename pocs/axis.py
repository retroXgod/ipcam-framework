import requests

def check(ip, port=80):
    schemes = ['http', 'https'] if port in [443, 8443, 9443] else ['http']
    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}/axis-cgi/admin/param.cgi?action=list"
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200 and "root" in r.text:
                return True, "Axis camera exposed admin params (possible info leak)"
        except Exception:
            continue
    return False, ""

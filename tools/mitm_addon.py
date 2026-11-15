"""mitmproxy addon: log Samsung account/OSP/OAuth traffic in cleartext to a file."""
import json, time
from mitmproxy import http

LOG = "mitm_oauth.log"
INTEREST = ("account.samsung", "samsungiots", "samsungiotcloud", "st-av.net",
            "oauth", "token", "authcode", "auth_code", "account.smartthings",
            "api.smartthings", "configuration", "osp", "accountant", "signin", "authorize")

def _w(*a):
    line = f"{time.strftime('%H:%M:%S')} " + " ".join(str(x) for x in a)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def _hot(host, url):
    h = (host + " " + url).lower()
    return any(k in h for k in INTEREST)

def request(flow: http.HTTPFlow):
    r = flow.request
    if not _hot(r.host, r.pretty_url):
        return
    _w("\n>>> REQ", r.method, r.pretty_url)
    for k in ("authorization", "x-osp-appid", "x-iot-scope", "content-type", "user-agent"):
        if k in r.headers: _w("    H", k + ":", r.headers[k][:200])
    body = r.get_text(strict=False) or ""
    if body: _w("    BODY", body[:1500])

def response(flow: http.HTTPFlow):
    r = flow.request
    if not _hot(r.host, r.pretty_url):
        return
    resp = flow.response
    _w("<<< RSP", resp.status_code, r.method, r.pretty_url)
    body = resp.get_text(strict=False) or ""
    # surface the juicy fields
    for key in ("client_id", "clientId", "authCode", "auth_code", "access_token",
                "accessToken", "code", "redirect", "scope", "api_server_url", "cis"):
        if key in body:
            _w("    *HIT*", key, "present in response")
    if body: _w("    BODY", body[:1500])

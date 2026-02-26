# Writeup: Jetpack Drift — BITSCTF Forensics

## Challenge Description

> _The download failed, but the investigation didn't. Before vanishing, a researcher captured the raw exchange between a broken server and a nosy client. Sift through the packets to recover what was lost._

A single file is provided: `chall.pcap` (500 KB, 312 packets).

**Flag:** `BITSCTF{LF1_st4nds_4_1ost_fr0m_1ns1d3}`

---

## Step 1 — Initial PCAP Reconnaissance

The first step is to identify the file type and obtain basic statistics:

```bash
file chall.pcap
# pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v2)

capinfos chall.pcap
# 312 packets, 500 KB, duration ~119 seconds
# Capture interfaces: docker0, br-0eeb176485d4, eth0
```

The capture is **Linux cooked-mode v2**, which suggests it was taken in a Docker environment (bridge interfaces). This tells us there is a server running in a container.

---

## Step 2 — Traffic Analysis with tcpdump

Since `tshark` has a dissector bug with this particular file, we use `tcpdump` to list the packets:

```bash
tcpdump -r chall.pcap -nn 2>/dev/null | grep HTTP
```

This reveals HTTP requests between the client (`172.18.0.1`) and the Docker server (`172.18.0.10:80`):

| #   | Method | URI                | Client Port | Response      |
| --- | ------ | ------------------ | ----------- | ------------- |
| 1   | GET    | `/`                | 56276       | 200 OK        |
| 2   | GET    | `/manifest.json`   | 53566       | 200 OK        |
| 3   | GET    | `/robots.txt`      | 36276       | 200 OK        |
| 4   | GET    | `/send-chunks.php` | 46460       | 200 OK        |
| 5   | GET    | `/encryption.py`   | 54622       | 200 OK        |
| 6   | GET    | `/favicon.ico`     | 33678       | 404 Not Found |
| 7   | GET    | `/database.sql`    | 39764       | 200 OK        |

There is also traffic to external IPs (`185.125.190.96` — connectivity check, and `151.101.65.91` — TLS connection), but they are not relevant to the challenge.

The host targeted by all requests is: **`storagejetpack.in`** (visible in the `Host` header of each request).

---

## Step 3 — HTTP Content Extraction with Scapy

As `tshark` fails with this PCAP, we use **Scapy** in Python to reconstruct the TCP streams and extract the content of each HTTP response. The technique is:

1. Filter packets by source IP (`172.18.0.10`), source port (`80`), and destination port (which identifies each request).
2. Deduplicate by TCP sequence number.
3. Sort by sequence number.
4. Concatenate payloads and separate HTTP headers from the body.

```python
from scapy.all import *

pkts = rdpcap('chall.pcap')
segments = []
seen = set()
for pkt in pkts:
    if pkt.haslayer('TCP') and pkt.haslayer('Raw'):
        tcp = pkt['TCP']
        ip = pkt['IP']
        if ip.src == '172.18.0.10' and tcp.sport == 80 and tcp.dport == PUERTO_DESTINO:
            seq = tcp.seq
            if seq not in seen:
                seen.add(seq)
                segments.append((seq, bytes(tcp.payload)))

segments.sort(key=lambda x: x[0])
data = b''.join(s[1] for s in segments)
headers, body = data.split(b'\r\n\r\n', 1)
```

This pattern is repeated for each resource. We analyze each one below.

---

## Step 4 — Main Page (`GET /`)

The response is an HTML page titled **"Welcome Portal"**:

```html
<div class="box">
  <h1 id="welcome">Welcome</h1>
  <p>Your session has been successfully initialized.</p>
  <p>Please proceed to the dashboard.</p>
</div>

<script>
  const nameParts = [
    String.fromCharCode(116),
    String.fromCharCode(121),
    String.fromCharCode(108),
    String.fromCharCode(101),
    String.fromCharCode(114),
  ];
  const user = nameParts.join("");
  document.getElementById("welcome").innerText += " " + user;
</script>
```

The JavaScript script constructs a username from obfuscated ASCII codes using `String.fromCharCode()`:

| Code | Character |
| ---- | --------- |
| 116  | t         |
| 121  | y         |
| 108  | l         |
| 101  | e         |
| 114  | r         |

**The user is: `tyler`**. This name will be key later.

---

## Step 5 — Database (`GET /database.sql`)

the `database.sql` file contains a full SQL dump with a table named `passwdbase` containing 250 users and their credentials:

```sql
CREATE TABLE IF NOT EXISTS `passwdbase` (
    `username` VARCHAR(50) NULL DEFAULT NULL,
    `email`    VARCHAR(50) NULL DEFAULT NULL,
    `password` VARCHAR(50) NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `passwdbase`(`username`,`email`,`password`) VALUES
('anorvell0', 'dharwick0@state.tx.us', '0X8xd44HAJo3xuhS@'),
('gbagehot1', 'arizzetti1@google.ca', 'uq9FUjF4LOYOL6H9'),
...
-- 250 users in total
```

Knowing the user is named **tyler** (Step 4), we search the table:

```
('tyler13bradley', 'lolagen31@pagesperso-orange.fr', '1VL7p6Rcli8mxgkh')
```

**Tyler's password is: `1VL7p6Rcli8mxgkh`**

---

## Step 6 — Encryption Script (`GET /encryption.py`)

This file reveals exactly how the downloaded content was encrypted. Key parts of the script include:

```python
from Crypto.Cipher import AES
from Crypto.Util import Counter
from database.sql import passwdbase.user
password = user.password
CHUNK_SIZE = 12800
```

The script imports the user's password directly from the database and defines the encryption functions:

### Encryption Algorithm

1. **Split** the original file into chunks of **12800 bytes**.
2. **Initial Key**: `SHA256(password)` — where `password` is the plaintext user password.
3. **Encrypt** each chunk using **AES-CTR**, using the first 16 bytes of the key as the counter's nonce/IV.
4. **Derive Next Key**: after encrypting each chunk, the new key is `SHA256(plaintext_chunk)` — the hash of the chunk **before** encryption.
5. **Last Chunk**: its `NXTCHNKHASH` is `0000...0000` (64 zeros), indicating the end of the chain.

```python
def encrypt_ctr(data, key):
    nonce = key[:16]
    counter = Counter.new(128, initial_value=int.from_bytes(nonce, 'big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.encrypt(data)

def encrypt_with_forward_header(input_file):
    chunks = split_file(input_file)
    initial_key = sha256(password.encode("utf-8"))

    encrypted_chunks = []
    prev_key = initial_key

    for chunk in chunks:
        encrypted = encrypt_ctr(chunk, prev_key)
        encrypted_chunks.append(encrypted)
        prev_key = sha256(chunk)  # next key = hash of plaintext

    # Each chunk is stored with a header: NXTCHNKHASH:<hash_of_next_encrypted_chunk>DATA:<data>
```

### Chunk Format

Each stored chunk has the following structure:

```
NXTCHNKHASH:<sha256_hex_of_next_encrypted_chunk>DATA:<encrypted_binary_data>
```

The `NXTCHNKHASH` field contains the **SHA256 of the next encrypted chunk**, creating a linked chain for correct reassembly.

---

## Step 7 — Chunked Download (`GET /send-chunks.php`)

The server response uses **HTTP Chunked Transfer Encoding** (`Transfer-Encoding: chunked`). Inside each HTTP chunk is a block in the format described above.

**10 chunks** are received. Parsing the chunked body:

```
Chunk size (hex)\r\n
Chunk data\r\n
...
0\r\n  (end)
```

Each data chunk follows the `NXTCHNKHASH:...DATA:...` format.

### Received Chunks (Arrival Order):

| Order | Own SHA256 (first 32 chars)        | NXTCHNKHASH (first 32 chars)       | Data Size   |
| ----- | ---------------------------------- | ---------------------------------- | ----------- |
| 0     | `e1fe90c30bf8168dbcf5230b37601b18` | `00000000000000000000000000000000` | 7034 bytes  |
| 1     | `6220acf3e605b9ec810366885f932c04` | `e1fe90c30bf8168dbcf5230b37601b18` | 12800 bytes |
| 2     | `b177a926e8f62b636310ae5f5d315539` | `cb862aef976f90522a06d9d50a9ae54f` | 12800 bytes |
| 3     | `760ebb08ae93519920baecb495bce57c` | `9a603acce8497cf1af44caba9f2ecee6` | 12800 bytes |
| 4     | `5eb82bfcb413ac56cf221698cd549ea5` | `dc34ed867659d48374bc56753a1e3fe1` | 12800 bytes |
| 5     | `7b01bea7c28e9392d2cd901ef34d2ac8` | `a4a4c1946f4b634c949fcc3699596429` | 12800 bytes |
| 6     | `cb862aef976f90522a06d9d50a9ae54f` | `5eb82bfcb413ac56cf221698cd549ea5` | 12800 bytes |
| 7     | `dc34ed867659d48374bc56753a1e3fe1` | `760ebb08ae93519920baecb495bce57c` | 12800 bytes |
| 8     | `a4a4c1946f4b634c949fcc3699596429` | `b177a926e8f62b636310ae5f5d315539` | 12800 bytes |
| 9     | `9a603acce8497cf1af44caba9f2ecee6` | `6220acf3e605b9ec810366885f932c04` | 12800 bytes |

The trick: **chunks arrived out of order** (the "broken server" from the description). Concatenating them as they arrived yields incoherent data.

---

## Step 8 — Reordering Chunks via Hash Chain

The `NXTCHNKHASH` field of each chunk contains the SHA256 of the **next** encrypted chunk, forming a linked list:

```
Chunk A  --NXTCHNKHASH-->  Chunk B  --NXTCHNKHASH-->  Chunk C  --> ...  --> 0000...0000 (end)
```

### Reordering Algorithm

1. Calculate the SHA256 of each chunk's encrypted data.
2. Build a map: `{own_hash: (next_hash, data)}`.
3. Find the **first chunk**: the one whose SHA256 **does not appear** as any other chunk's `NXTCHNKHASH` (no one points to it as "next").
4. Follow the `NXTCHNKHASH` chain until reaching `0000...0000`.

```python
# Build map
chunk_map = {}  # {own_hash: (next_hash, data)}
for chunk in parsed_chunks:
    own_hash = sha256_hex(chunk.data)
    chunk_map[own_hash] = (chunk.next_hash, chunk.data)

# Find start: hash not referenced by any NXTCHNKHASH
all_hashes = set(chunk_map.keys())
referenced = set(nh for nh, _ in chunk_map.values() if nh != '0' * 64)
start_hash = (all_hashes - referenced).pop()
# start_hash = 7b01bea7c28e9392d2cd901ef34d2ac8...
```

### Resulting Chain (Correct Order):

```
7b01bea7... -> a4a4c194... -> b177a926... -> cb862aef... -> 5eb82bfc... ->
dc34ed86... -> 760ebb08... -> 9a603acc... -> 6220acf3... -> e1fe90c3... -> END
```

**The correct order is: 5, 8, 2, 6, 4, 7, 3, 9, 1, 0** (arrival order indices).

---

## Step 9 — AES-CTR Decryption

With chunks in the correct order and Tyler's password, we can reverse the encryption:

```python
from Crypto.Cipher import AES
from Crypto.Util import Counter
import hashlib

password = "1VL7p6Rcli8mxgkh"
initial_key = hashlib.sha256(password.encode("utf-8")).digest()

decrypted_chunks = []
prev_key = initial_key

for encrypted_chunk in ordered_chunks:
    # Decrypt with AES-CTR (same function as encrypt, CTR is symmetric)
    nonce = prev_key[:16]
    counter = Counter.new(128, initial_value=int.from_bytes(nonce, 'big'))
    cipher = AES.new(prev_key, AES.MODE_CTR, counter=counter)
    plaintext = cipher.decrypt(encrypted_chunk)
    decrypted_chunks.append(plaintext)
    # Next key is SHA256 of the plaintext we just recovered
    prev_key = hashlib.sha256(plaintext).digest()

result = b''.join(decrypted_chunks)
# Total: 122234 bytes
```

**Note on AES-CTR**: Counter mode is symmetric; the `encrypt` operation works for both encryption and decryption given the correct key and nonce/counter.

**Note on Key Derivation**: Each chunk uses a different key derived from the previous chunk's plaintext. If chunks are out of order, only the first one decrypts correctly; the rest become garbage.

---

## Step 10 — Decrypted File Analysis

The resulting 122234-byte file is a **polyglot** (multiple valid formats in one file):

```
Offset 0-5:      ICO header (reserved=0, type=1, count=1)
Offset 6-21:     ICO image entry (256x256, 32bpp, data at offset 3801)
Offset 22-255:   Padding with "<!--" (HTML comment camouflage)
Offset 256-287:  MP4 ftyp box (isom, compatible: iso2, avc1, mp41)
Offset 288-3800: MP4 moov box (video metadata)
Offset 3801-21015: PNG image data (900x732, RGBA, 17215 bytes) — embedded as ICO image
Offset 21016-122233: MP4 mdat box (H.264 video + AAC audio data)
```

The file is simultaneously:

- A valid **ICO** (icon with an embedded PNG)
- A valid **MP4** (4-second video, 720x1272, H.264 + AAC)

### PNG Extraction

The PNG starts at offset 3801 (where the ICO points for its image data):

```python
png_start = 3801
iend_offset = data.find(b'IEND')
png_data = data[png_start:iend_offset + 8]  # +8 for IEND(4) + CRC(4)
```

---

## Step 11 — The Flag

Viewing the extracted PNG (900x732 pixels) clearly reveals the flag text on a light background:

```
BITSCTF{LF1_st4nds_4_1ost_fr0m_1ns1d3}
```

Reading as: **"LF1 stands 4 lost from inside"**.

---

## Complete Solver Script

```python
#!/usr/bin/env python3
"""Solver for Jetpack Drift — BITSCTF Forensics"""

import hashlib
import re
from scapy.all import rdpcap
from Crypto.Cipher import AES
from Crypto.Util import Counter

PCAP_FILE = "chall.pcap"

def sha256(data):
    return hashlib.sha256(data).digest()

def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()

def extract_http_body(pkts, src_ip, src_port, dst_port):
    """Reconstructs HTTP body from a TCP stream."""
    segments = []
    seen = set()
    for pkt in pkts:
        if pkt.haslayer('TCP') and pkt.haslayer('Raw'):
            tcp = pkt['TCP']
            ip = pkt['IP']
            if ip.src == src_ip and tcp.sport == src_port and tcp.dport == dst_port:
                seq = tcp.seq
                if seq not in seen:
                    seen.add(seq)
                    segments.append((seq, bytes(tcp.payload)))
    segments.sort(key=lambda x: x[0])
    data = b''.join(s[1] for s in segments)
    _, body = data.split(b'\r\n\r\n', 1)
    return body

def parse_chunked_body(body):
    """Parses a Transfer-Encoding: chunked body."""
    chunks = []
    pos = 0
    while pos < len(body):
        end = body.find(b'\r\n', pos)
        if end == -1:
            break
        chunk_size = int(body[pos:end].decode('ascii'), 16)
        if chunk_size == 0:
            break
        pos = end + 2
        chunks.append(body[pos:pos + chunk_size])
        pos += chunk_size + 2
    return chunks

def main():
    print("[*] Reading PCAP...")
    pkts = rdpcap(PCAP_FILE)

    # 1. Extract database.sql and find Tyler's password
    print("[*] Extracting database.sql...")
    sql = extract_http_body(pkts, '172.18.0.10', 80, 39764).decode()
    users = re.findall(r"\('([^']+)',\s*'([^']+)',\s*'([^']+)'\)", sql)
    password = None
    for username, email, pwd in users:
        if 'tyler' in username:
            password = pwd
            print(f"[+] Found user: {username} -> password: {password}")
            break

    # 2. Extract encrypted chunks from send-chunks.php
    print("[*] Extracting encrypted chunks...")
    body = extract_http_body(pkts, '172.18.0.10', 80, 46460)
    raw_chunks = parse_chunked_body(body)

    # 3. Parse and build hash map
    chunk_map = {}
    for raw in raw_chunks:
        h_start = raw.find(b'NXTCHNKHASH:') + len(b'NXTCHNKHASH:')
        d_start = raw.find(b'DATA:') + len(b'DATA:')
        next_hash = raw[h_start:raw.find(b'DATA:')].decode()
        enc_data = raw[d_start:]
        own_hash = sha256_hex(enc_data)
        chunk_map[own_hash] = (next_hash, enc_data)

    # 4. Reorder via hash chain
    print("[*] Reordering chunks...")
    all_hashes = set(chunk_map.keys())
    referenced = set(nh for nh, _ in chunk_map.values() if nh != '0' * 64)
    current = (all_hashes - referenced).pop()

    ordered = []
    while current in chunk_map:
        nh, data = chunk_map[current]
        ordered.append(data)
        if nh == '0' * 64:
            break
        current = nh
    print(f"[+] {len(ordered)} chunks reordered")

    # 5. AES-CTR Decryption
    print("[*] Decrypting...")
    key = sha256(password.encode('utf-8'))
    decrypted = []
    for chunk in ordered:
        nonce = key[:16]
        ctr = Counter.new(128, initial_value=int.from_bytes(nonce, 'big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        plain = cipher.decrypt(chunk)
        decrypted.append(plain)
        key = sha256(plain)

    result = b''.join(decrypted)
    print(f"[+] Decrypted: {len(result)} bytes")

    # 6. Extract PNG
    png_start = result.find(b'\x89PNG')
    iend = result.find(b'IEND')
    png = result[png_start:iend + 8]

    with open('flag.png', 'wb') as f:
        f.write(png)
    print(f"[+] PNG extracted: flag.png ({len(png)} bytes)")
    print("[+] Open flag.png to see the flag!")

if __name__ == '__main__':
    main()
```

---

## Solution Chain Summary

```
chall.pcap
    |
    |-- GET /                --> Username: "tyler" (obfuscated in JS)
    |-- GET /database.sql    --> Tyler's password: "1VL7p6Rcli8mxgkh"
    |-- GET /encryption.py   --> Encryption algorithm (AES-CTR + hash chain)
    |-- GET /send-chunks.php --> 10 encrypted chunks OUT OF ORDER
    |
    v
Reorder chunks (following NXTCHNKHASH linked list)
    |
    v
Decrypt AES-CTR (Initial key = SHA256(password), subsequent = SHA256(plaintext))
    |
    v
Polyglot ICO/MP4 file with embedded PNG
    |
    v
flag.png --> BITSCTF{LF1_st4nds_4_1ost_fr0m_1ns1d3}
```

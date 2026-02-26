# Detailed Guide: Solving "Chaos in the Wire" (Forensics CTF)

This guide exhaustively documents the process of analysis, discovery, and exploitation of the covert channel present in the `chaos.pcap` file.

---

## Step 1: Initial Traffic Exploration

The analysis began with a superficial inspection of the `chaos.pcap` file using `strings` and `tshark`.

```bash
strings chaos.pcap | head -n 20
tshark -r chaos.pcap -c 10
```

**Findings:**

1.  **Initial HTTP Request:** Client `192.168.1.25` requests `network_notes.txt` from server `10.0.0.80`.
2.  **Notes Content:** The `network_notes.txt` file contained critical clues:
    - "Sequence numbers and acknowledgements are 32-bit values."
    - "IPv4 addresses are also 32-bit integers when represented numerically."
    - "Metadata carries meaning beyond its intended purpose."
    - "This is the first time this has happened in 32 years" (Reference to 32-bit values).

---

## Step 2: Identification of the Anomaly

After the notes were downloaded, the traffic changed drastically. Hundreds of packets marked as "SSL" or "TLS" began arriving at `10.0.0.80` from a wide variety of external IP addresses.

**Forensic Observation:**

- The payloads of these packets contained no readable data (they appeared as noise or encryption).
- The challenge description indicated that exfiltration **did not depend on the application layer**.
- This led us to investigate the **TCP and IP headers**.

---

## Step 3: Discovery of the Covert Channel

Based on the "32 bits" clue, we tested mathematical operations between header fields. Our hypothesis was that the exfiltrated file data was hidden using an **XOR** operation.

### Test 1: Source IP XOR Sequence Number

We used the first packet of the exfiltration stream (Packet #6 in the pcap).

- **Source IP (19.235.231.6)** -> `0x13EB E706`
- **TCP Sequence Number** -> `0x2491 5BA9`
- **Operation:** `0x13EB E706 ^ 0x2491 5BA9 = 37 7A BC AF`

**Eureka!** `37 7A BC AF` are the first 4 bytes of a **7-Zip** magic signature.

### Test 2: Source IP XOR Acknowledgment Number

To obtain the next bytes of the header (`27 1C` for 7-Zip):

- **TCP Ack Number** -> `0x34F7 FD1A`
- **Operation:** `0x13EB E706 ^ 0x34F7 FD1A = 27 1C 1A 1C`

This confirmed that each packet carried **8 bytes** of hidden data:

1.  4 bytes in the `Sequence Number` field.
2.  4 bytes in the `Acknowledgment Number` field.

---

## Step 4: Automated Extraction with Python

We created a script (`final_extraction.py`) using the `scapy` library to process all packets and reconstruct the binary file.

```python
from scapy.all import rdpcap, TCP, IP
import struct

def ip_to_int(ip):
    return struct.unpack("!I", struct.pack("!BBBB", *map(int, ip.split('.'))))[0]

pkts = rdpcap('chaos.pcap')
file_data = bytearray()

# Process from packet 6 onwards
for pkt in pkts[5:]:
    if IP in pkt and TCP in pkt and pkt[IP].dst == '10.0.0.80':
        src_int = ip_to_int(pkt[IP].src)
        # Extract 8 bytes per packet via XOR
        file_data.extend(struct.pack(">I", src_int ^ pkt[TCP].seq))
        file_data.extend(struct.pack(">I", src_int ^ pkt[TCP].ack))

with open("final_flag.7z", "wb") as f:
    f.write(file_data)
```

---

## Step 5: Analysis of the 7-Zip Container

Upon extracting the `final_flag.7z` file, we encountered a `chaos_source/` folder containing **200 ELF binary files** (Linux executables) of 14 KB each.

```bash
7z x final_flag.7z
ls chaos_source/
```

**Metadata Analysis:**
Listing the files with technical details revealed that the **modification timestamps** were incremental and very precise. This suggested the files should be processed in chronological order.

---

## Step 6: Coordinated Execution and Flag Retrieval

Each of the 200 binaries printed a small portion of a text string. We wrote a final script (`run_all.py`) to automate execution in the correct order.

```python
import os, subprocess

# Sort files by modification time (mtime)
files = sorted([os.path.join('chaos_source', f) for f in os.listdir('chaos_source')],
               key=os.path.getmtime)

output = ""
for f in files:
    os.chmod(f, 0o755) # Ensure execution permissions
    res = subprocess.run([f], capture_output=True, text=True)
    output += res.stdout.strip()

print(output)
```

**Execution Result:**
The script printed a fragment from the novel _Norwegian Wood_ by Haruki Murakami, and camouflaged within the text appeared the flag:

**`BITSCTF{v0l4t1l3_junk_m4th_c4nt_h1d3_th3_trutH}`**

---

## Technical Conclusions

1.  **Covert Channel:** The challenge exploited trust in TCP headers, using control fields (Seq/Ack) to transport arbitrary data.
2.  **Obfuscation:** Using XOR with the source IP made the sequence numbers appear random and valid at first glance.
3.  **Fragmentation:** The flag was not in a single place but divided into 200 pieces of executable code, requiring file metadata analysis (timestamps) for final reconstruction.

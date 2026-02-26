# Safe Not Safe - BITSCTF 2025 (Reversing)

> **Category:** Reverse Engineering
> **Difficulty:** Medium-High
> **Flag:** `BITSCTF{7h15_41n7_53cur3_571ll_n07_p47ch1ng_17}`
> **Description:** _I forgot the password to my smart safe :( Luckily, I was able to dump the firmware._

---

## 1. Initial Reconnaissance

### 1.1. Provided Files

Upon downloading the challenge, we find the following files:

```
dist/
├── Dockerfile
├── flag.txt      # Local placeholder: "test{flag}"
├── run.sh
└── zImage        # 13 MB - ARM Linux Kernel
```

### 1.2. Dockerfile Analysis

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    qemu-system-arm \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf
WORKDIR /challenge
COPY zImage run.sh flag.txt ./

RUN chmod +x run.sh && \
    chown -R ctf:ctf /challenge && \
    chmod 440 flag.txt

USER ctf
EXPOSE 1337

CMD sh -c 'exec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/challenge/run.sh,pty,stderr,echo=0'
```

**Key Observations:**

- `qemu-system-arm` and `socat` are installed.
- `socat` listens on port **1337** and redirects each connection to `run.sh`.
- The flag is in `flag.txt` with permissions 440 (read-only for owner `ctf`).

### 1.3. run.sh Analysis

```bash
#!/bin/bash
qemu-system-arm \
  -M virt \
  -cpu cortex-a15 \
  -m 128M \
  -nographic \
  -kernel /challenge/zImage \
  -append "console=ttyAMA0 quiet oops=panic panic=1 rdinit=/init" \
  -no-reboot \
  -snapshot \
  -drive file=/challenge/flag.txt,format=raw,if=none,readonly=on,id=flagdrive \
  -device virtio-blk-device,drive=flagdrive \
  -monitor /dev/null
```

**Key Observations:**

- An ARM virtual machine is started using QEMU.
- The `zImage` kernel boots with `rdinit=/init`, indicating an **initramfs** embedded within the kernel.
- The flag is mounted as a **virtio block device** (`/dev/vda`) inside the VM in read-only mode.
- The QEMU monitor is redirected to `/dev/null` (no direct QEMU interaction).

**Conclusion:** We need to extract the initramfs from the `zImage` to find the binary controlling access to the flag.

---

## 2. Extracting the Initramfs

### 2.1. File Identification

```bash
$ file zImage
zImage: Linux kernel ARM boot executable zImage (kernel >=v4.15) (little-endian)
```

A `zImage` is a compressed Linux kernel using gzip. Inside the decompressed kernel, there is typically a compressed initramfs embedded.

### 2.2. Locating Compressed Data

We search for gzip signatures (`\x1f\x8b\x08`) within the `zImage`:

```python
data = open('zImage','rb').read()
for i in range(len(data)-2):
    if data[i] == 0x1f and data[i+1] == 0x8b and data[i+2] == 0x08:
        print(f'gzip at offset 0x{i:x}')
```

```
gzip at offset 0xf4b4      # <-- Compressed kernel
gzip at offset 0x8eaf8f    # <-- Garbage/trailing data
```

### 2.3. Decompressing the Kernel

We extract the first gzip (the compressed ARM kernel):

```bash
$ python3 -c "open('kernel.gz','wb').write(open('zImage','rb').read()[0xf4b4:])"
$ gzip -d kernel.gz
$ file kernel
kernel: data   # Decompressed ARM kernel (~33 MB)
```

### 2.4. Finding the Initramfs inside the Kernel

In the decompressed kernel, we search for another gzip containing the initramfs:

```python
data = open('kernel','rb').read()
# Search for gzip
for i in range(len(data)-2):
    if data[i] == 0x1f and data[i+1] == 0x8b and data[i+2] == 0x08:
        print(f'gzip at 0x{i:x}')
```

```
gzip at 0x1b5dca4   # <-- Compressed initramfs
```

### 2.5. Extracting and Decompressing the Initramfs

```bash
$ python3 -c "open('initramfs.gz','wb').write(open('kernel','rb').read()[0x1b5dca4:])"
$ gzip -d initramfs.gz
$ file initramfs
initramfs: ASCII cpio archive (SVR4 with no CRC)
```

### 2.6. Extracting CPIO Content

```bash
$ mkdir initramfs_extracted && cd initramfs_extracted
$ cpio -idmv < ../initramfs
```

Resulting structure:

```
initramfs_extracted/
├── bin/
│   ├── busybox
│   ├── sh -> busybox
│   ├── cat, ls, mount, echo, ...
├── challenge/
│   └── lock_app          # <-- TARGET BINARY
├── dev/
├── etc/
├── init                   # <-- Boot script
├── proc/
├── sys/
└── ...
```

---

## 3. Analysis of the `init` Script

```bash
#!/bin/sh

# 1. Mount virtual filesystems
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp

# 2. Hardening
echo 1 >/proc/sys/kernel/kptr_restrict
echo 1 >/proc/sys/kernel/dmesg_restrict
echo 2 >/proc/sys/kernel/perf_event_paranoid

# 3. Set up user identity files
echo "root:x:0:0:root:/root:/bin/sh" >/etc/passwd
echo "player:x:1000:1000:player:/home/player:/bin/sh" >>/etc/passwd

# 5. Lock down system files
chown -R root:root /bin /sbin /etc /usr /init

# 6. Setup player environment
chown -R root:root /challenge/lock_app
chmod +s /challenge/lock_app    # <-- SETUID!

echo "Welcome! Run \`/challenge/lock_app\` to get started."

# 7. Drop privileges and launch shell
exec setsid cttyhack setuidgid 1000 sh
```

**Key Points:**

- `lock_app` has the **setuid** bit set and is owned by root.
- User privileges are dropped to UID 1000 (`player`) before giving a shell.
- `lock_app` can read `/dev/vda` (the flag) because it runs as root (setuid).

---

## 4. Reverse Engineering `lock_app`

### 4.1. Binary Identification

```bash
$ file lock_app
lock_app: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV),
          statically linked, for GNU/Linux 3.2.0, stripped
```

- **ARM 32-bit**, statically linked with glibc, **stripped** (no symbols).
- Being static, it includes all of glibc (~559 KB).

### 4.2. Relevant Strings

```bash
$ strings lock_app | grep -E "password|flag|code|access|gift|vda|Reset|challenge"
```

```
Initialzed internal lock systems.
The current time is: %llu
/dev/urandom
     PASSWORD RESET VERIFICATION
Your challenge code is: %06u
Enter the response code to reset your password.
Challenge is valid for the next %d seconds.
Challenge has expired. Be faster next time.
Response code:
      PASSWORD RESET SUCCESSFUL
Nope. Try again.
1. Enter access code
2. Reset password
3. Exit
Select option:
Enter access code:
Uhhh... We ran out of budget before implementing this part...
/dev/vda
Here's a gift: %s
```

### 4.3. Disassembly with Radare2

Using `r2` for disassembly. User functions are identified by searching for references to key strings (user functions are in the `0x10400-0x10f00` range, separate from glibc).

#### Identified Functions:

| Address   | Name (assigned)        | Description                                    |
| --------- | ---------------------- | ---------------------------------------------- |
| `0x1055c` | `init_crypto()`        | Initializes PRNG and builds S-box              |
| `0x10704` | `substitute()`         | Applies byte-by-byte substitution using S-box  |
| `0x1079c` | `generate_challenge()` | Generates challenge code and expected response |
| `0x109b8` | `verify_response()`    | Verifies user response                         |
| `0x10a34` | `reset_password()`     | Full password reset flow                       |
| `0x10b90` | `print_menu()`         | Prints main menu                               |
| `0x10bf4` | `enter_access_code()`  | Option 1 (not implemented)                     |
| `0x10d0c` | `main()`               | Main function                                  |
| `0x10efc` | `read_flag()`          | Reads `/dev/vda` and prints flag               |

---

## 5. Detailed Analysis of Each Function

### 5.1. main() - `0x10d0c`

Reconstructed pseudocode:

```c
int main() {
    init_crypto();              // Initialize S-box

    // Print banner
    printf("╔═══════════════════════════════════╗\n");
    printf("║   Unbreakable Smart Locks, Co.    ║\n");
    printf("║ \"Truly unbreakable - guaranteed.\" ║\n");
    printf("╚═══════════════════════════════════╝\n");

    int attempts = 0;

    while (1) {
        print_menu();
        int choice;
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                enter_access_code();  // "Ran out of budget..."
                attempts++;
                if (attempts > 2)
                    printf("Have you tried resetting the password?\n");
                break;
            case 2:
                if (reset_password() != 0)
                    return 0;  // Exit after success
                break;
            case 3:
                printf("Goodbye.\n");
                return 0;
            default:
                printf("Invalid option.\n");
        }
    }
}
```

**Observation:** Option 1 ("Enter access code") is not implemented. The correct path is Option 2 ("Reset password"). If the reset fails, we return to the menu and can try again.

### 5.2. init_crypto() - `0x1055c`

This function is **critical**. It initializes a cryptographic system based on a random S-box (substitution table).

```c
void init_crypto() {
    // 1. Get current timestamp
    time_t time1 = time(0);

    // 2. Seed PRNG with timestamp
    srand(time1);

    // 3. Consume 2 random values (not used for S-box)
    rand();  // discarded
    rand();  // discarded

    // 4. Print information
    printf("Initialzed internal lock systems.\n");
    printf("The current time is: %llu\n", time1);  // <-- SEED LEAK!

    // 5. Initialize S-box as identity permutation
    uint8_t S[256];  // at address 0xa845c
    for (int i = 0; i <= 255; i++)
        S[i] = i;

    // 6. Fisher-Yates shuffle (generates a random permutation)
    for (int i = 255; i > 0; i--) {
        int j = rand() % (i + 1);
        // Swap S[i] and S[j]
        uint8_t temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    // 7. Build inverse S-box
    uint8_t S_inv[256];  // at address 0xa855c
    for (int i = 0; i <= 255; i++)
        S_inv[S[i]] = i;
}
```

**Key Vulnerability:** The program prints `time1`, which is exactly the **seed** used for `srand()`. Knowing the seed, we can **reproduce the entire `rand()` sequence** and reconstruct the S-box.

### 5.3. substitute() - `0x10704`

Applies the S-box byte-by-byte to a 32-bit value:

```c
uint32_t substitute(uint32_t val) {
    uint8_t b0 = val & 0xFF;
    uint8_t b1 = (val >> 8) & 0xFF;
    uint8_t b2 = (val >> 16) & 0xFF;
    uint8_t b3 = (val >> 24) & 0xFF;

    return (S[b3] << 24) | (S[b2] << 16) | (S[b1] << 8) | S[b0];
}
```

Each byte of the value is replaced independently using the S-box. This is equivalent to how S-boxes work in AES but with a random table.

### 5.4. generate_challenge() - `0x1079c`

Generates the challenge code and calculates the expected response internally:

```c
void generate_challenge() {
    // 1. RE-SEED the PRNG with a new timestamp
    time_t time2 = time(0);
    srand(time2);

    // 2. Generate two random values
    int r1 = rand();
    int r2 = rand();

    // 3. Apply the S-box (built in init_crypto)
    uint32_t s1 = substitute(r1);
    uint32_t s2 = substitute(r2);

    // 4. Read 4 random bytes from /dev/urandom
    uint32_t urandom_val;
    FILE *f = fopen("/dev/urandom", "r");
    fread(&urandom_val, 1, 4, f);
    fclose(f);

    // 5. Calculate challenge code
    uint32_t val1 = ((s1 * 31337 + s2) & 0xFFFFFFFF) % 1000000;
    uint32_t challenge_code = urandom_val ^ val1;

    // 6. Calculate expected response
    uint32_t val2 = (s1 ^ s2) % 1000000;
    uint32_t expected_response = urandom_val ^ val2;

    // 7. Save to global variables
    global_challenge = challenge_code;    // @ 0xa865c
    global_response  = expected_response; // @ 0xa8660
    global_time      = time2;             // @ 0xa8664

    // 8. Show to user
    printf("Your challenge code is: %06u\n", challenge_code);
    printf("Enter the response code to reset your password.\n");
    printf("Challenge is valid for the next 30 seconds.\n");
}
```

**Note on constant 31337:** In hex, this is `0x7A69`, a classic hacker nod (leet speak: "elite").

**Note on modulo 1000000:** The compiler optimizes `% 1000000` using the "magic number multiplication trick":

```
r * 0x431BDE83 >> 50  ≈  r / 1000000
```

Then it computes `r - (r/1000000) * 1000000` for the remainder. Reconstruction confirming the modulo:

- `((31 * 64 - 31) * 8 + 1) * 64 = 1000000`.

### 5.5. verify_response() - `0x109b8`

```c
int verify_response(uint32_t user_response) {
    time_t now = time(0);

    // Check timeout (30 seconds)
    if (now - global_time > 30) {
        printf("Challenge has expired. Be faster next time.\n");
        return 0;
    }

    // Compare response
    if (user_response == global_response)
        return 1;  // SUCCESS!
    else
        return 0;  // Failure
}
```

### 5.6. reset_password() - `0x10a34`

```c
int reset_password() {
    generate_challenge();

    printf("Response code: ");
    uint32_t user_input;
    if (scanf("%u", &user_input) != 1) {
        printf("[!] Invalid input.\n");
        return 0;
    }

    if (verify_response(user_input)) {
        printf("PASSWORD RESET SUCCESSFUL\n");
        read_flag();     // <-- READS AND PRINTS FLAG!
        return 1;
    } else {
        printf("Nope. Try again.\n");
        return 0;
    }
}
```

### 5.7. read_flag() - `0x10efc`

```c
void read_flag() {
    FILE *f = fopen("/dev/vda", "r");
    if (!f) {
        printf("error opening file! contact the challenge author.\n");
        exit(1);
    }
    char buf[100];
    fgets(buf, 100, f);
    fclose(f);
    printf("Here's a gift: %s\n", buf);
}
```

---

## 6. The Cryptographic Vulnerability

### 6.1. What we know as the attacker

When interacting with the service, we obtain:

1. **`time1`** - Printed directly: `"The current time is: 1771687408"` --> **S-box seed.**
2. **`challenge_code`** - Printed directly: `"Your challenge code is: 3893264580"`
3. **`time2`** - NOT printed, but it's `time(0)` at challenge generation. Since we automate the interaction, `time2 ≈ time1` (same second).

### 6.2. XOR Cancellation

The algorithm calculates:

```
challenge_code    = urandom_val  XOR  val1
expected_response = urandom_val  XOR  val2
```

Where:

- `val1 = (s1 * 31337 + s2) % 1000000` (deterministic if time1 and time2 are known)
- `val2 = (s1 ^ s2) % 1000000` (deterministic if time1 and time2 are known)
- `urandom_val` is true random (4 bytes from `/dev/urandom`) and **unknown**.

However, if we XOR both equations:

```
challenge_code XOR expected_response = val1 XOR val2
```

Rearranging:

```
expected_response = challenge_code XOR val1 XOR val2
```

**The `urandom_val` cancels out completely!** We don't need to know it.

### 6.3. Reproducing PRNG State

To calculate `val1` and `val2`, we need `s1` and `s2`, which depend on:

1. **The S-box** - Determined by `time1` (the given seed).
2. **`r1` and `r2`** - Determined by `time2` (the second seed).

#### S-box Reconstruction:

```python
import ctypes
libc = ctypes.CDLL("libc.so.6")

def build_sbox(time1):
    libc.srand(time1)
    libc.rand()  # discarded
    libc.rand()  # discarded

    S = list(range(256))
    for i in range(255, 0, -1):
        j = libc.rand() % (i + 1)
        S[i], S[j] = S[j], S[i]

    return S
```

**Important Note:** We use `ctypes` to call `srand()` and `rand()` from **glibc** directly. This is necessary because glibc uses a non-trivial PRNG (TYPE_3 polynomial feedback with 31-word table) that pure Python implementations may not match.

#### Calculating r1, r2:

```python
libc.srand(time2)
r1 = libc.rand()
r2 = libc.rand()
```

#### Calculating s1, s2:

```python
def substitute(val, S):
    b0 = val & 0xFF
    b1 = (val >> 8) & 0xFF
    b2 = (val >> 16) & 0xFF
    b3 = (val >> 24) & 0xFF
    return (S[b3] << 24) | (S[b2] << 16) | (S[b1] << 8) | S[b0]

s1 = substitute(r1, S)
s2 = substitute(r2, S)
```

#### Calculating Response:

```python
val1 = ((s1 * 31337 + s2) & 0xFFFFFFFF) % 1000000
val2 = (s1 ^ s2) % 1000000
response = challenge_code ^ val1 ^ val2
```

---

## 7. Exploitation Strategy

### 7.1. Attack Diagram

```
                        SERVICE                           ATTACKER
                        ========                           ========

   init_crypto():
   ┌─ time1 = time(0)
   ├─ srand(time1)                                  1. Read time1 from
   ├─ 2x rand() discarded                               program output
   ├─ Build S-box with 255x rand()
   └─ Print: "The current time is: {time1}" ──────> time1 known!
                                                         │
   generate_challenge():                                │
   ┌─ time2 = time(0)                                  │ 2. time2 ≈ time1
   ├─ srand(time2)                                      │    (fast automation)
   ├─ r1 = rand(), r2 = rand()                         │
   ├─ s1 = S(r1), s2 = S(r2)                           │ 3. Reconstruct S-box
   ├─ urandom = read("/dev/urandom", 4)                 │    with srand(time1)
   ├─ val1 = (s1*31337 + s2) % 1000000                 │
   ├─ challenge = urandom ^ val1                        │ 4. Reconstruct r1,r2
   ├─ val2 = (s1 ^ s2) % 1000000                       │    with srand(time2)
   ├─ response = urandom ^ val2                         │
   └─ Print: "challenge code: {challenge}" ──────>   │ 5. Calculate:
                                                         │    val1, val2
   verify_response():                                   │
   ┌─ Read user input <────────────────────────────── 6. Send:
   ├─ Compare with response                                response = challenge
   └─ If match: read_flag()                                          ^ val1 ^ val2
          │
          └──> "Here's a gift: BITSCTF{...}" ────────> FLAG!
```

### 7.2. Handling time2

- `time1` is obtained at program start.
- `time2` is generated when we choose Option 2.
- With fast automation, **`time2 == time1`** (same second).
- If there's a delay, **we can retry**: failure returns us to the menu for another challenge with a new `time2`.
- Our solver tests `time2 = time1, time1+1, time1+2, ...` incrementally.

---

## 8. Full Exploit

```python
#!/usr/bin/env python3
"""
Solver for 'Safe Not Safe' - BITSCTF 2025

Key insight:
  challenge_code    = urandom XOR val1
  expected_response = urandom XOR val2

Therefore:
  response = challenge_code XOR val1 XOR val2

urandom cancels out. val1 and val2 are deterministic
if time1 (printed) and time2 (≈ time1) are known.
"""

import ctypes
import socket
import re
import sys
import time

# Load system glibc to reproduce srand()/rand()
libc = ctypes.CDLL("libc.so.6")
libc.srand.argtypes = [ctypes.c_uint]
libc.srand.restype = None
libc.rand.argtypes = []
libc.rand.restype = ctypes.c_int


def build_sbox(time1):
    """Reconstruct the S-box generated during init_crypto()."""
    libc.srand(ctypes.c_uint(time1))
    libc.rand()  # first rand() discarded by init
    libc.rand()  # second rand() discarded by init

    # Identity permutation
    sbox = list(range(256))

    # Fisher-Yates shuffle (255 iterations, 255 rand() calls)
    for i in range(255, 0, -1):
        j = libc.rand() % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]

    return sbox


def substitute(val, sbox):
    """Byte-by-byte substitution with the S-box."""
    b0 = val & 0xFF
    b1 = (val >> 8) & 0xFF
    b2 = (val >> 16) & 0xFF
    b3 = (val >> 24) & 0xFF
    return (sbox[b3] << 24) | (sbox[b2] << 16) | (sbox[b1] << 8) | sbox[b0]


def compute_response(time1, time2, challenge_code):
    """Calculate the correct response."""
    sbox = build_sbox(time1)

    # Reproduce challenge PRNG
    libc.srand(ctypes.c_uint(time2))
    r1 = libc.rand()
    r2 = libc.rand()

    s1 = substitute(r1, sbox)
    s2 = substitute(r2, sbox)

    val1 = ((s1 * 31337 + s2) & 0xFFFFFFFF) % 1000000
    val2 = (s1 ^ s2) % 1000000

    # Magic: urandom cancels in XOR
    response = challenge_code ^ val1 ^ val2
    return response


def recvuntil(sock, pattern, timeout=60):
    """Receive data until pattern is found."""
    sock.settimeout(timeout)
    data = b""
    while pattern not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def solve(host, port):
    print(f"[*] Connecting to {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # Wait for VM shell
    data = recvuntil(sock, b"$ ", timeout=120)
    print("[*] Shell obtained inside QEMU VM")

    # Run the binary
    sock.sendall(b"/challenge/lock_app\n")
    data = recvuntil(sock, b"Select option: ")
    text = data.decode("utf-8", errors="replace")

    # Extract time1 (PRNG seed)
    time1 = int(re.search(r"The current time is: (\d+)", text).group(1))
    print(f"[*] time1 (PRNG seed) = {time1}")

    # Choice 2: Reset password
    sock.sendall(b"2\n")
    data = recvuntil(sock, b"Response code: ")
    text = data.decode("utf-8", errors="replace")

    # Extract challenge code
    challenge_code = int(re.search(r"challenge code is: (\d+)", text).group(1))
    print(f"[*] challenge_code = {challenge_code}")

    # Try time2 = time1, time1+1, ...
    for delta in range(0, 30):
        time2 = time1 + delta
        response = compute_response(time1, time2, challenge_code)
        print(f"[*] delta={delta}, time2={time2}, response={response}")

        sock.sendall(f"{response}\n".encode())

        data = recvuntil(sock, b"Select option: ", timeout=10)
        text = data.decode("utf-8", errors="replace")

        if "PASSWORD RESET SUCCESSFUL" in text or "gift" in text:
            print(text)
            print("[+] FLAG OBTAINED!")
            break
        elif "Nope" in text or "expired" in text:
            print(f"[*] Failed with delta={delta}, retrying...")
            sock.sendall(b"2\n")
            data = recvuntil(sock, b"Response code: ")
            text = data.decode("utf-8", errors="replace")
            challenge_code = int(re.search(r"challenge code is: (\d+)", text).group(1))
            print(f"[*] New challenge_code = {challenge_code}")

    sock.close()


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
    solve(host, port)
```

---

## 9. Execution and Result

### 9.1. Execution against Remote Server

```
$ python3 solve.py 135.235.195.203 3000

[*] Connecting to 135.235.195.203:3000...
[*] Shell obtained inside QEMU VM
[*] time1 (PRNG seed) = 1771687408
[*] challenge_code = 3893264580
[*] delta=0, time2=1771687408, response=3892479912

╔══════════════════════════════════════╗
║      PASSWORD RESET SUCCESSFUL       ║
╚══════════════════════════════════════╝
Here's a gift: BITSCTF{7h15_41n7_53cur3_571ll_n07_p47ch1ng_17}

[+] FLAG OBTAINED!
```

**Flag:** `BITSCTF{7h15_41n7_53cur3_571ll_n07_p47ch1ng_17}`

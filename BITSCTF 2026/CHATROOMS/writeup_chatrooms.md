# ChatRooms - Full CTF Writeup

**Challenge:** ChatRooms
**Category:** Pwn / Crypto
**Flag:** `BITSCTF{3CD54_n0nc3_n0nc3nc3_676767}`
**Server:** `nc 20.193.149.152 1342`
**Curve:** SECP256k1 (the same as Bitcoin)
**Hash:** SHA-256

---

## Table of Contents

1. [General Description](#1-general-description)
2. [Protocol Reconnaissance](#2-protocol-reconnaissance)
3. [Room 1 - Alpha_01: Constant Nonce](#3-room-1---alpha_01-constant-nonce)
4. [Room 2 - Exarch_01: LCG Nonce with Rachel's Parameters](#4-room-2---exarch_01-lcg-nonce-with-rachels-parameters)
5. [Room 3 - Cracked_Core: Degree-2 Polynomial Recurrence (Polynonce)](#5-room-3---cracked_core-degree-2-polynomial-recurrence-polynonce)
6. [Detailed Mathematics](#6-detailed-mathematics)
7. [Full Final Script](#7-full-final-script)

---

## 1. General Description

The challenge consists of an **interactive TCP chatroom** where different members send messages signed with **ECDSA over the SECP256k1 curve**. Each room has a vulnerable member whose nonce generation has a different cryptographic weakness. The objective is to **recover the private key `d`** of each vulnerable member and send it to the server in hexadecimal format preceded by `0x` to advance to the next room.

The challenge has **3 rooms** with incremental difficulty:

| Room | Vulnerable Member | Vulnerability                                                    | Difficulty |
| ---- | ----------------- | ---------------------------------------------------------------- | ---------- |
| 1    | Alpha_01          | Constant Nonce (`k = 0xDEADC0DE`)                                | Easy       |
| 2    | Exarch_01         | LCG Nonce (`k2 = A*k1 + B mod N`)                                | Medium     |
| 3    | Cracked_Core      | Degree-2 Polynomial Recurrence (`k_{i+1} = a*k_i^2 + b*k_i + c`) | Hard       |

**All keys are session-dependent** - they change with each TCP connection. Recovery and submission must be done within the same session.

---

## 2. Protocol Reconnaissance

### Connection

Upon connecting to the server (`nc 20.193.149.152 1342`), an interactive chatroom is presented with a `User:` prompt. The primary interaction is through the `@boss` command, which causes the chatroom members to send signed messages.

### Message Format

Server messages follow this format:

```
[MEMBER_NAME]: message text
    Sig: r=0x..., s=0x...
User:
```

Or with a prefix:

```
User: [MEMBER_NAME]: message text
    Sig: r=0x..., s=0x...
```

### ECDSA Signature

Each message is accompanied by an ECDSA signature `(r, s)` over the **SECP256k1** curve:

- **Curve:** SECP256k1 (order `N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`)
- **Generator:** `G` (SECP256k1 base point)
- **Hash:** `z = SHA256(message) mod N`
- **Signature:** `s = k^{-1} * (z + r*d) mod N` where:
  - `k` = nonce (ephemeral random number)
  - `d` = private key
  - `r` = x-coordinate of the point `k*G`

### Regex Expressions for Parsing

```python
# Clean ANSI terminal codes
ANSI_RE = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")

# Parse message: [User]: text
MSG_RE = re.compile(r"^(?:User:\s*)?\[(\w+)\]:\s*(.*)$")

# Parse signature: Sig: r=0x..., s=0x...
SIG_RE = re.compile(r"^Sig:\s*r=(0x[0-9a-f]+),\s*s=(0x[0-9a-f]+)$", re.I)
```

### BOSS Hints

Each room has a BOSS that provides hints when using `@boss`:

- **Room 1:** _"All the important people sign their messages to prove authenticity."_
- **Room 2:** _"Some rely on random-looking tricks to stay hidden. But if you find the pattern, the trick falls apart."_
- **Room 3:** _"There seems to be a weak pattern in whatever this crazy guy is saying."_ + _"Retrieve the secret to go to the next chatroom."_

### Key Submission Format

The private key is sent as a hexadecimal number:

```
0x<hex_private_key>
```

The server responds with `[SYSTEM]: Room X Key Validated.` if it is correct.

---

## 3. Room 1 - Alpha_01: Constant Nonce

### Observation

When analyzing **Alpha_01** signatures, the `r` value is observed to be **identical in all signatures**:

```
r = 0x20b964ead5037915921e2887a069a08fb57e1213c1c11d0b7e230aff96e9456f
```

In ECDSA, `r` is the x-coordinate of the point `k*G`. If `r` is always the same, it means `k` is always the same: **Alpha_01 reuses a constant nonce**.

### Nonce Identification

Through brute force on small values or by analyzing the challenge name, it is determined that:

```
k = 0xDEADC0DE
```

It can be verified: `(0xDEADC0DE * G).x() mod N == R_ALPHA` (true).

### Private Key Recovery

From the ECDSA signature equation:

```
s = k^{-1} * (z + r*d) mod N
```

Solving for `d`:

```
s * k = z + r*d  mod N
d = (s*k - z) * r^{-1}  mod N
```

With `k = 0xDEADC0DE` known, `z = SHA256(msg) mod N`, and `(r, s)` from the signature, we calculate `d` directly.

### Implementation

```python
R_ALPHA = 0x20b964ead5037915921e2887a069a08fb57e1213c1c11d0b7e230aff96e9456f
K_ALPHA = 0xDEADC0DE

def H(msg):
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big") % N

def solve_room1(msg, s_hex):
    z = H(msg)
    s = int(s_hex, 16) % N
    return ((s * K_ALPHA - z) % N) * pow(R_ALPHA, -1, N) % N
```

### Flow

1. Send `@boss`
2. Receive message from Alpha_01 with signature `(r, s)`
3. Calculate `d = (s * 0xDEADC0DE - z) * r^{-1} mod N`
4. Send `0x<hex_d>`
5. Receive `[SYSTEM]: Room 1 Key Validated.`

---

## 4. Room 2 - Exarch_01: LCG Nonce with Rachel's Parameters

### Observation

Room 2 has two relevant members:

- **Exarch_01**: Sends messages signed with ECDSA. The `r` values are **different** between signatures, so there is no direct nonce reuse. However, the nonces follow an **LCG (Linear Congruential Generator)** relationship.
- **Rachel_Relay**: Sends messages with data fragments:

```
[Rachel_Relay]: Processing data fragment A_CHUNK:1a2b3c4d | B_CHUNK:5e6f7a8b
```

### Discovery of LCG Parameters

Rachel_Relay sends exactly **8 pairs of chunks**, each 8 hexadecimal characters (32 bits). By **concatenating** the 8 A_CHUNKs, one obtains a 256-bit number which is the **multiplier `A`** of the LCG, and by concatenating the 8 B_CHUNKs, one obtains the **increment `B`**:

```python
# Rachel sends 8 pairs: (A_CHUNK_1, B_CHUNK_1), ..., (A_CHUNK_8, B_CHUNK_8)
# Concatenation: A = A_CHUNK_1 || A_CHUNK_2 || ... || A_CHUNK_8  (256 bits)
#                B = B_CHUNK_1 || B_CHUNK_2 || ... || B_CHUNK_8  (256 bits)

A = int("".join(a_chunks), 16) % N
B = int("".join(b_chunks), 16) % N
```

### LCG Relationship between Nonces

Exarch_01 nonces follow:

```
k_2 = A * k_1 + B  mod N
```

### Private Key Recovery

Given two signatures from Exarch_01 `(r1, s1, z1)` and `(r2, s2, z2)`, and knowing that `k_i = s_i^{-1} * (z_i + r_i*d)`:

```
k_2 = A * k_1 + B
(z2 + r2*d) / s2 = A * (z1 + r1*d) / s1 + B
```

Expanding and grouping `d` terms:

```
(r2/s2 - A*r1/s1) * d = A*z1/s1 - z2/s2 + B
```

Solving:

```
coef = r2*s1^{-1} - A*r1*s2^{-1}    (all mod N)
rhs  = A*z1*s1^{-1} - z2*s2^{-1} + B
d    = rhs * coef^{-1}  mod N
```

### Verification

It is verified that the recovered nonces satisfy the LCG relationship:

```python
k1 = (z1 + r1*d) * s1^{-1} mod N
k2 = (z2 + r2*d) * s2^{-1} mod N
assert (k2 - (A*k1 + B)) % N == 0  # If it fails, the solution is incorrect
```

### Implementation

```python
def concat_chunks(pairs, key):
    return int("".join(p[key] for p in pairs), 16) % N

def solve_lcg_d_room2(ex1, ex2, A, B):
    r1, s1, z1 = int(ex1["r"],16)%N, int(ex1["s"],16)%N, H(ex1["msg"])
    r2, s2, z2 = int(ex2["r"],16)%N, int(ex2["s"],16)%N, H(ex2["msg"])
    invs1, invs2 = pow(s1,-1,N), pow(s2,-1,N)
    coef = (r2*invs2 - A*r1*invs1) % N
    if coef == 0: return None
    rhs = (A*z1*invs1 - z2*invs2 + B) % N
    d = (rhs * pow(coef,-1,N)) % N
    # Verify
    k1 = ((z1+r1*d)*invs1) % N
    k2 = ((z2+r2*d)*invs2) % N
    if (k2 - (A*k1 + B)) % N != 0: return None
    return d
```

### Flow

1. Send `@boss` repeatedly
2. Collect 8 pairs of chunks from Rachel_Relay
3. Collect 2 signatures from Exarch_01
4. Concatenate chunks -> obtain `A` and `B`
5. Solve linear system for `d`
6. Send `0x<hex_d>`
7. Receive `[SYSTEM]: Room 2 Key Validated.`

---

## 5. Room 3 - Cracked_Core: Degree-2 Polynomial Recurrence (Polynonce)

### Observation

Room 3 has a single member: **Cracked_Core**. It sends 5 messages that cycle indefinitely:

1. _"Double down on the nonsense"_
2. _"Nothing lines up cleanly -- jagged edges all over."_
3. _"Feels like everything loops back eventually."_
4. _"I dug through old buffers and found nonsense everywhere."_
5. _"There's something off about this pattern -- can't place it."_

Each message has a unique signature `(r, s)` that is **fixed within the session** (the same message always produces the same signature). The 5 `r` values are all different -- **no direct nonce reuse**.

### BOSS Hint

> _"There seems to be a weak pattern in whatever this crazy guy is saying."_

The "weakness" is not in the messages themselves, but in the **relationship between the nonces**.

### Failed Attacks

Before finding the solution, the following were exhaustively tested:

- Constant nonce (same r) -- NO, all r are different
- Linear LCG (`k_{i+1} = a*k_i + b`) with all 120 permutations -- NO
- Polynomial in the index (linear, quadratic, cubic: `Delta^2=0, Delta^3=0, Delta^4=0`) -- NO
- Small nonces (`k < 100000`) -- NO
- `k = d` (nonce equal to key) -- NO
- `k = H(msg)` (nonce equal to message hash) -- NO
- Incremental nonce (`k_2 = k_1 + delta` for delta -1000..+1000) -- NO
- Small ratios (`k_i/k_j = p/q` for p,q < 30) -- NO
- Relationships with keys from previous rooms -- NO

### The Solution: Polynonce Attack (Degree-2 Polynomial Recurrence)

The vulnerability is a **quadratic polynomial recurrence** between the nonces:

```
k_{i+1} = a * k_i^2 + b * k_i + c   mod N
```

This is different from a polynomial in the index. Here each nonce is a **quadratic function of the previous nonce**. This type of weakness was described in the Kudelski Security paper on attacks against polynomial recurrences of ECDSA nonces.

**Reference:** https://github.com/kudelskisecurity/ecdsa-polynomial-nonce-recurrence-attack

### Degree-2 Attack Mathematics

#### Step 1: Represent nonces as polynomials in `d`

From the ECDSA equation `s = k^{-1}(z + rd)`, we solve:

```
k_i = s_i^{-1} * (z_i + r_i * d) = alpha_i + beta_i * d
```

Where `alpha_i = z_i * s_i^{-1} mod N` and `beta_i = r_i * s_i^{-1} mod N`.

Each nonce `k_i` is a **degree-1 polynomial in the unknown `d`**: `[alpha_i, beta_i]`.

#### Step 2: Calculate differences and sums

We define:

- `delta_i = k_{i+1} - k_i` (degree-1 polynomial in `d`)
- `sigma_i = k_i + k_{i+1}` (degree-1 polynomial in `d`)

#### Step 3: Quadratic recurrence property

If `k_{i+1} = f(k_i)` with `f` of degree 2, then the following holds:

```
delta_{i+1} / delta_i = a * sigma_i + b
```

Where `a` and `b` are the recurrence coefficients. This gives three equations (for i=0,1,2):

```
delta_1/delta_0 = a*sigma_0 + b    ... (P0)
delta_2/delta_1 = a*sigma_1 + b    ... (P1)
delta_3/delta_2 = a*sigma_2 + b    ... (P2)
```

#### Step 4: Eliminate `a` and `b`

Subtracting P0-P1 and P1-P2:

```
(delta_1/delta_0 - delta_2/delta_1) = a*(sigma_0 - sigma_1)
(delta_2/delta_1 - delta_3/delta_2) = a*(sigma_1 - sigma_2)
```

Dividing to eliminate `a`:

```
(delta_1/delta_0 - delta_2/delta_1) * (sigma_1 - sigma_2) =
(delta_2/delta_1 - delta_3/delta_2) * (sigma_0 - sigma_1)
```

Multiplying by `delta_0 * delta_1 * delta_2` to clear denominators:

```
(delta_1^2 - delta_0*delta_2) * delta_2 * (sigma_1 - sigma_2) =
(delta_2^2 - delta_1*delta_3) * delta_0 * (sigma_0 - sigma_1)
```

#### Step 5: Polynomial equation in `d`

Since each `delta_i` and `sigma_i` are degree-1 polynomials in `d`, the resulting equation is a **degree-4 polynomial in `d`**. Its roots are candidates for the private key.

#### Step 6: Find roots with Cantor-Zassenhaus

To find the roots of the degree-4 polynomial over `GF(N)`:

1. **Calculate `gcd(f(x), x^N - x)`**: This yields the product of all linear factors (roots in GF(N)). Polynomial modular exponentiation (`poly_powmod`) is used to calculate `x^N mod f(x)`.

2. **Factorize with Cantor-Zassenhaus**: If the GCD has degree > 1, the probabilistic Cantor-Zassenhaus algorithm is used:
   - Choose a random `r`
   - Calculate `gcd(h, (r+x)^{(N-1)/2} - 1)`
   - This separates approximately half of the roots
   - Repeat recursively until linear factors are obtained

3. **Extract roots**: From each linear factor `(x - root)`, the root is `-c_0/c_1`.

#### Step 7: Verification and Permutations

We do not know the **order** in which the nonces were generated (the recurrence depends on the order). With 5 signatures, we test all **120 possible permutations** of 5 elements. For each permutation:

1. Construct the polynomial equation
2. Find roots
3. **Verify** each candidate root against a signature NOT used in the equation, via elliptic curve multiplication: `(k*G).x == r`

The winning permutation was `(2, 4, 3, 0, 1)`, meaning the nonces were generated in the order: sig[2] -> sig[4] -> sig[3] -> sig[0] -> sig[1].

### Implementation of Polynomial Arithmetic

```python
# Polynomial = list of coefficients [c0, c1, c2, ...]
# Represents c0 + c1*x + c2*x^2 + ...

def poly_strip(p):
    """Removes trailing zeros"""
    while len(p) > 1 and p[-1] == 0:
        p = p[:-1]
    return p

def poly_add(a, b):
    """Addition of polynomials mod N"""
    n = max(len(a), len(b))
    result = [0]*n
    for i in range(len(a)): result[i] = (result[i] + a[i]) % N
    for i in range(len(b)): result[i] = (result[i] + b[i]) % N
    return poly_strip(result)

def poly_sub(a, b):
    """Subtraction of polynomials mod N"""
    n = max(len(a), len(b))
    result = [0]*n
    for i in range(len(a)): result[i] = (result[i] + a[i]) % N
    for i in range(len(b)): result[i] = (result[i] - b[i]) % N
    return poly_strip(result)

def poly_mul(a, b):
    """Multiplication of polynomials mod N"""
    if len(a) == 0 or len(b) == 0: return [0]
    result = [0] * (len(a) + len(b) - 1)
    for i in range(len(a)):
        for j in range(len(b)):
            result[i+j] = (result[i+j] + a[i] * b[j]) % N
    return poly_strip(result)

def poly_mod(a, b):
    """Polynomial remainder: a mod b"""
    a = list(a)
    while len(a) >= len(b) and any(x != 0 for x in a):
        if a[-1] == 0: a.pop(); continue
        coeff = (a[-1] * pow(b[-1], -1, N)) % N
        shift = len(a) - len(b)
        for i in range(len(b)):
            a[shift + i] = (a[shift + i] - coeff * b[i]) % N
        while len(a) > 1 and a[-1] == 0: a.pop()
    return a

def poly_powmod(base, exp, modpoly):
    """Modular exponentiation: base^exp mod modpoly (square-and-multiply)"""
    result = [1]
    base = poly_mod(base, modpoly)
    while exp > 0:
        if exp & 1:
            result = poly_mod(poly_mul(result, base), modpoly)
        base = poly_mod(poly_mul(base, base), modpoly)
        exp >>= 1
    return result
```

### Candidate Key Verification

```python
def verify_key_single(d, sig):
    """Verifies d against a signature using elliptic curve multiplication"""
    r = int(sig['r'], 16) % N
    s = int(sig['s'], 16) % N
    z = H(sig['msg'])
    k = ((z + r * d) * pow(s, -1, N)) % N
    if k == 0: return False
    return (k * G).x() % N == r  # Scalar multiplication in SECP256k1
```

### Full Flow for Room 3

1. Send `@boss` repeatedly (0.8s interval)
2. Collect 5 unique signatures from Cracked_Core
3. For each permutation of the 5 signatures:
   a. Construct `delta_i = k_{i+1} - k_i` and `sigma_i = k_i + k_{i+1}` as polynomials in `d`
   b. Construct the degree-4 equation: `LHS - RHS = 0`
   c. Find roots with Cantor-Zassenhaus
   d. Verify each root against a remaining signature
4. Send the verified key: `0x<hex_d>`
5. Receive `[SYSTEM]: Room 3 Key Validated.`
6. Receive the flag: `BITSCTF{3CD54_n0nc3_n0nc3nc3_676767}`

---

## 6. Detailed Mathematics

### ECDSA: Quick Review

**Key generation:**

- Private key: `d` (random integer in [1, N-1])
- Public key: `Q = d * G` (point on the curve)

**Message `m` signing:**

1. Calculate `z = SHA256(m) mod N`
2. Choose random nonce `k` in [1, N-1]
3. Calculate point `R = k * G`
4. `r = R.x mod N` (x-coordinate)
5. `s = k^{-1} * (z + r*d) mod N`
6. Signature: `(r, s)`

**From the signature it is deduced:**

```
k = s^{-1} * (z + r*d) mod N
```

### Room 1: Known Nonce

If `k` is known:

```
d = (s*k - z) * r^{-1} mod N
```

### Room 2: Linear Relationship between Nonces (LCG)

Given:

- `k1 = (z1 + r1*d) * s1^{-1}`
- `k2 = (z2 + r2*d) * s2^{-1}`
- Relationship: `k2 = A*k1 + B`

Substituting:

```
(z2 + r2*d)/s2 = A*(z1 + r1*d)/s1 + B
```

Multiplying by `s1*s2`:

```
s1*(z2 + r2*d) = A*s2*(z1 + r1*d) + B*s1*s2
```

Grouping `d`:

```
d * (s1*r2 - A*s2*r1) = A*s2*z1 - s1*z2 + B*s1*s2
```

Simplifying with modular inverses:

```
d = (A*z1/s1 - z2/s2 + B) / (r2/s2 - A*r1/s1)  mod N
```

### Room 3: Quadratic Recurrence

The recurrence `k_{i+1} = a*k_i^2 + b*k_i + c` implies:

```
k_{i+1} - k_i = a*(k_{i+1}^2 - k_i^2)/(k_{i+1} - k_i) * (k_{i+1} - k_i) + ...
```

More elegantly, using the property that for `f(x) = ax^2 + bx + c`:

```
f(k_{i+1}) - f(k_i) = a*(k_{i+1}^2 - k_i^2) + b*(k_{i+1} - k_i)
                      = (k_{i+1} - k_i) * [a*(k_{i+1} + k_i) + b]
```

That is:

```
delta_{i+1} = delta_i * (a * sigma_i + b)
```

Where `delta_i = k_{i+1} - k_i` and `sigma_i = k_{i+1} + k_i`.

This allows clearing the unknown coefficients `a` and `b` with 3 equations (requiring 5 nonces = 5 signatures), leaving a **degree-4 polynomial equation in the single unknown `d`**.

---

## 7. Full Final Script

The final script (`solve_chatrooms.py`) automatically solves all 3 rooms in a single TCP connection. It is included below in this same repository.

### Execution

```bash
source venv/bin/activate
python3 solve_chatrooms.py
```

### Expected Output

```
[*] Connected
[+] -> Room 2
[+] d2 solved
[+] -> Room 3!
[R3] Sig #1: Feels like everything loops back eventua
[R3] Sig #2: Nothing lines up cleanly -- jagged edges
[R3] Sig #3: I dug through old buffers and found nons
[R3] Sig #4: Double down on the nonsense
[R3] Sig #5: There's something off about this pattern
  *** FOUND! Degree-2 recurrence, order=(2, 4, 3, 0, 1)
  d3 = 0x...
[+] -> Room 4!!

*** VAULT OPEN ***
FLAG: BITSCTF{3CD54_n0nc3_n0nc3nc3_676767}
```

### Dependencies

```bash
pip install ecdsa
```

(`ecdsa` is only needed for the elliptic curve operations. The rest are standard Python modules.)

---

## Summary

| Room | Vulnerability               | Data Needed                        | Technique                     |
| ---- | --------------------------- | ---------------------------------- | ----------------------------- |
| 1    | `k = 0xDEADC0DE` constant   | 1 Alpha_01 signature               | Direct solving                |
| 2    | `k2 = A*k1 + B` (LCG)       | 2 Exarch_01 sigs + 8 chunks Rachel | Linear system                 |
| 3    | `k_{i+1} = a*k_i^2+b*k_i+c` | 5 Cracked_Core signatures          | Polynonce + Cantor-Zassenhaus |

**Flag:** `BITSCTF{3CD54_n0nc3_n0nc3nc3_676767}`

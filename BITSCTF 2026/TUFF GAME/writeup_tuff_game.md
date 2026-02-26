# Tuff Game - BITSCTF Reverse Engineering Challenge Writeup

**Category:** Reverse Engineering
**Points:** 472
**Author:** Swif7Bl8ze
**Solves:** 1 (100% liked)

> My friend Kekwman has challenged me to defeat this game, reach a million metres and help me defeat his score

## Overview

Tuff Game is a Unity-based Windows game that challenges players to reach 1,000,000 metres. The flag is hidden behind **three layers of decoys** designed to mislead reverse engineers. The real flag is encoded as a QR code assembled from 900 small texture tiles embedded in the game assets.

---

## Step 1: Initial Reconnaissance

The challenge provides a Windows Unity game build. Listing the contents reveals the standard Unity structure:

```
$ ls -la Tuff_Game/
Tuff_Game.exe
UnityPlayer.dll
UnityCrashHandler64.exe
MonoBleedingEdge/
Tuff_Game_Data/
```

![File Structure](writeup_assets/file_structure.png)

The presence of the `MonoBleedingEdge/` directory is a critical finding: it means the game uses the **Mono scripting backend** (not IL2CPP). This is great news for us because it means `Assembly-CSharp.dll` is a standard .NET assembly that can be decompiled directly into readable C# code, no need to reverse native binaries.

Checking `app.info` confirms the game identity:

```
$ cat Tuff_Game_Data/app.info
BITSKrieg
Tuff_Game
```

The key file we care about is:

```
Tuff_Game_Data/Managed/Assembly-CSharp.dll
```

This DLL contains all the custom game logic written by the challenge author.

---

## Step 2: Decompiling the Game Logic

We use **ILSpy** (via the `ilspycmd` CLI tool) to decompile `Assembly-CSharp.dll` back into readable C#:

```bash
$ ilspycmd Tuff_Game_Data/Managed/Assembly-CSharp.dll > decompiled.cs
```

Scrolling through the decompiled output, several classes immediately stand out:

| Class | Purpose |
|---|---|
| `NotAFlag` | Contains RSA-style `BigInteger` values (n1-n9, ciphertext) |
| `FlagGeneration` | Contains a byte array XOR-encrypted with key `0x5A` |
| `ScoreManaged` | Manages the score and shows a flag image at 1M metres |
| `DistanceScoreManager` | Tracks distance traveled in the game |

The class names themselves are already suspicious: `NotAFlag` is literally saying "this is not a flag", and `FlagGeneration` seems too obvious. Let's dig into each one.

---

## Step 3: Red Herring #1 - XOR Decryption (FlagGeneration)

The `FlagGeneration` class contains a hardcoded encrypted byte array and a trivially simple XOR decryption method:

```csharp
public class FlagGeneration : MonoBehaviour
{
    private const byte KEY = 90; // 0x5A

    private readonly byte[] encryptedFlag = new byte[51]
    {
        33, 15, 55, 55, 5, 110, 57, 46, 47, 59,
        54, 54, 35, 5, 47, 52, 34, 106, 40, 107,
        107, 52, 61, 5, 46, 106, 5, 61, 105, 46,
        5, 60, 54, 110, 61, 5, 41, 105, 105, 55,
        41, 5, 46, 106, 106, 5, 105, 110, 41, 35,
        39
    };

    private string decryptFlag()
    {
        byte[] array = new byte[encryptedFlag.Length];
        for (int i = 0; i < encryptedFlag.Length; i++)
        {
            array[i] = (byte)(encryptedFlag[i] ^ 0x5A);
        }
        return Encoding.ASCII.GetString(array);
    }
}
```

The decryption is a simple single-byte XOR with `0x5A` (90 in decimal). We can replicate this trivially in Python:

```python
enc = [33,15,55,55,5,110,57,46,47,59,54,54,35,5,47,52,34,106,40,107,
       107,52,61,5,46,106,5,61,105,46,5,60,54,110,61,5,41,105,105,55,
       41,5,46,106,106,5,105,110,41,35,39]
print(''.join(chr(b ^ 0x5A) for b in enc))
```

![XOR Decryption Result](writeup_assets/xor_decryption.png)

**Result:** `{Umm_4ctually_unx0r11ng_t0_g3t_fl4g_s33ms_t00_34sy}`

The message translates to: *"Umm, actually unxoring to get flag seems too easy"*. The challenge author is literally taunting us. Notice it also lacks the `BITSCTF` prefix, confirming this is **NOT the flag** - it's the first decoy.

---

## Step 4: Red Herring #2 - RSA Decryption (NotAFlag)

The next suspicious class is `NotAFlag`. The name alone should raise eyebrows, but it's easy to overlook when you see what looks like legitimate cryptographic data. The class contains 9 RSA moduli and a ciphertext, all as `BigInteger` values:

```csharp
public class NotAFlag
{
    private static readonly BigInteger n1 = BigInteger.Parse("140381961641930398...");
    private static readonly BigInteger n2 = BigInteger.Parse("901326702501969623...");
    private static readonly BigInteger n3 = BigInteger.Parse("928704119750923541...");
    private static readonly BigInteger n4 = BigInteger.Parse("168059555628207778...");
    private static readonly BigInteger n5 = BigInteger.Parse("138034396036991389...");
    private static readonly BigInteger n6 = BigInteger.Parse("556265366680072175...");
    private static readonly BigInteger n7 = BigInteger.Parse("549978052370628066...");
    private static readonly BigInteger n8 = BigInteger.Parse("169970633954647104...");
    private static readonly BigInteger n9 = BigInteger.Parse("106902071352915984...");

    private static readonly BigInteger ciphertext = BigInteger.Parse("149967007359164586...");
}
```

Each `n` value is a ~1024-bit RSA modulus (product of two large primes). Having **multiple moduli** is a classic CTF crypto setup that hints at a **shared prime factor attack**: if any two moduli share a prime factor `p`, we can compute `p = GCD(ni, nj)` and then trivially factor both.

```python
from math import gcd

ns = [n1, n2, n3, n4, n5, n6, n7, n8, n9]

# Pairwise GCD to find shared prime factors
for i in range(len(ns)):
    for j in range(i+1, len(ns)):
        g = gcd(ns[i], ns[j])
        if g > 1:
            print(f"GCD(n{i+1}, n{j+1}) = {g}")
```

**Result:** `n6` and `n7` share a common prime factor! Now we can factor `n6` and perform standard RSA decryption:

```python
p = gcd(n6, n7)
q = n6 // p
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)
plaintext = pow(ciphertext, d, n6)
flag = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
print(flag)
```

![RSA Decryption Result](writeup_assets/rsa_decryption.png)

**Result:** `BITSCTF{https://blogs.mtdv.me/Crypt0}`

This time it even has the proper `BITSCTF{...}` flag format! It links to a crypto blog post. Very tempting to submit this as the answer... but the class is literally called **`NotAFlag`**. This is the **second decoy**.

---

## Step 5: Red Herring #3 - Flag Images in Assets

Having been burned twice by the decompiled code, let's look at what actually happens in the game. The `ScoreManaged` class reveals the core mechanic: when the player's distance reaches 1,000,000 metres, a flag **image** is displayed on screen:

```csharp
public class ScoreManaged : MonoBehaviour
{
    public float requiredDistance = 1000000f;
    public Image flagImage;
    private bool flagUnlocked;

    private void Update()
    {
        if (!flagUnlocked && GetCurrentScore() >= requiredDistance)
        {
            flagUnlocked = true;
            ShowFlagAndRetry();
        }
    }

    private void ShowFlagAndRetry()
    {
        if (flagImage != null)
            flagImage.gameObject.SetActive(value: true);
        if (retryScreenUI != null)
            retryScreenUI.SetActive(value: true);
        Time.timeScale = 0f;  // Pause game
    }
}
```

The flag isn't generated from code - it's an **image asset** (`flagImage`). So we need to extract textures from the Unity asset bundles. Using **UnityPy**:

```python
import UnityPy, os

env = UnityPy.load("Tuff_Game_Data/sharedassets0.assets")
for obj in env.objects:
    if obj.type.name == "Texture2D":
        data = obj.read()
        data.image.save(f"extracted/{data.m_Name}.png")
```

This extracts hundreds of textures. Sorting by file size, two large images immediately catch our eye:

```
-rw-r--r-- 1.4M Fl4g_second_Half.png
-rw-r--r-- 1.4M Fl4g_first_Half.png
```

**First Half (`Fl4g_first_Half.png`):**

![Fl4g First Half](writeup_assets/Fl4g_first_Half.png)

The image shows a character holding a sign that reads: `BITSCTF{D0` / `4ss 3sts...`

**Second Half (`Fl4g_second_Half.png`):**

![Fl4g Second Half](writeup_assets/Fl4g_second_Half.png)

This image shows another character with a sign that reads: `otcha, perhaps` / `think verticaly`

Combining them horizontally would give something like `BITSCTF{D0otcha, perhaps 4ss 3sts think verticaly` - which is clearly not a real flag. But the critical hint is in the text: **"perhaps think vertically"**.

This is telling us to look at the image data from a vertical/grid perspective. These flag images are the **third decoy**, but they contain the hint to the real solution.

---

## Step 6: The Real Flag - QR Code from Texture Tiles

Going back to the list of extracted textures, among the game sprites and UI elements, there are **900 tiny 5x5 pixel images** with a peculiar naming pattern:

```
rq_0_0.png   rq_0_1.png   rq_0_2.png   ... rq_0_29.png
rq_1_0.png   rq_1_1.png   rq_1_2.png   ... rq_1_29.png
...
rq_29_0.png  rq_29_1.png  rq_29_2.png  ... rq_29_29.png
```

![Sample rq Tiles](writeup_assets/sample_rq_tiles.png)

Key observations:
- **900 tiles** = 30 x 30 grid
- Each tile is **5x5 pixels** (black and white)
- The prefix `rq` is **`QR` reversed** - a hint!
- Combined they would form a **150x150 pixel image** - perfect QR code size

### Assembling the QR Code

The first attempt using coordinates as `(x, y)` directly produces a garbled result. Remembering the hint "think vertically", we try **swapping the coordinates** `(y, x)`:

```python
from PIL import Image
import re, os

rq_files = {}
for fname in os.listdir("extracted"):
    m = re.match(r'rq_(\d+)_(\d+)\.png', fname)
    if m:
        x, y = int(m.group(1)), int(m.group(2))
        rq_files[(x, y)] = f"extracted/{fname}"

# Create 150x150 image (30 tiles * 5px each)
result = Image.new('RGBA', (150, 150), (255, 255, 255, 255))

for (x, y), fpath in rq_files.items():
    tile = Image.open(fpath)
    # SWAP x and y coordinates (the key insight!)
    result.paste(tile, (y * 5, x * 5))

result.save("qr_assembled.png")
```

Here's the comparison between wrong and correct assembly:

![QR Comparison - Wrong vs Correct](writeup_assets/qr_comparison.png)

The correctly assembled QR code:

![Assembled QR Code](writeup_assets/qr_assembled_scaled.png)

### Decoding the QR Code

Using **pyzbar** to decode the assembled QR code (scaling up for better detection):

```python
from PIL import Image
from pyzbar.pyzbar import decode

img = Image.open("qr_assembled.png")
img = img.resize((600, 600), Image.NEAREST)  # Scale up for scanner
results = decode(img)
print(results[0].data.decode())
```

**Output:**

```
BITSCTF{Th1$_14_D3f1n1t3ly_Th3_fl4g}
```

---

## Flag

```
BITSCTF{Th1$_14_D3f1n1t3ly_Th3_fl4g}
```

*"This is definitely the flag"* - and this time, it truly is.

---

## Summary of Decoy Layers

The challenge was designed as a Russian nesting doll of red herrings, each more convincing than the last:

| Layer | Location | Technique | Result | Why It's Fake |
|---|---|---|---|---|
| 1 | `FlagGeneration` class | XOR with `0x5A` | `{Umm_4ctually_unx0r11ng_t0_g3t_fl4g_s33ms_t00_34sy}` | Self-referential taunt, no `BITSCTF` prefix |
| 2 | `NotAFlag` class | RSA with shared primes (GCD attack) | `BITSCTF{https://blogs.mtdv.me/Crypt0}` | Class literally named "NotAFlag" |
| 3 | `Fl4g_*_Half.png` images | Asset extraction | "perhaps think vertically" | Hint pointing to the real solution |
| **4** | **900 `rq_X_Y` texture tiles** | **QR code assembly (swap X,Y)** | **`BITSCTF{Th1$_14_D3f1n1t3ly_Th3_fl4g}`** | **The real flag!** |

---

## Full Solver Script

```python
#!/usr/bin/env python3
"""
Tuff Game - BITSCTF Solver
Extracts textures from Unity assets, assembles QR code, and decodes the flag.
"""

import UnityPy
import os
import re
from PIL import Image
from pyzbar.pyzbar import decode

# --- Step 1: Extract all textures from game assets ---
base = "Tuff_Game_Data"
output_dir = "extracted"
os.makedirs(output_dir, exist_ok=True)

for root, dirs, files in os.walk(base):
    for fname in files:
        fpath = os.path.join(root, fname)
        try:
            env = UnityPy.load(fpath)
            for obj in env.objects:
                if obj.type.name == "Texture2D":
                    data = obj.read()
                    name = data.m_Name
                    data.image.save(os.path.join(output_dir, f"{name}.png"))
        except:
            pass

# --- Step 2: Collect all QR tile fragments ---
rq_files = {}
max_coord = 0
for fname in os.listdir(output_dir):
    m = re.match(r'rq_(\d+)_(\d+)\.png', fname)
    if m:
        x, y = int(m.group(1)), int(m.group(2))
        rq_files[(x, y)] = os.path.join(output_dir, fname)
        max_coord = max(max_coord, x, y)

grid_size = max_coord + 1  # 30
tile_size = 5

# --- Step 3: Assemble QR code (swap X and Y!) ---
qr = Image.new('RGBA',
               (grid_size * tile_size, grid_size * tile_size),
               (255, 255, 255, 255))

for (x, y), fpath in rq_files.items():
    tile = Image.open(fpath)
    qr.paste(tile, (y * tile_size, x * tile_size))  # SWAP!

# --- Step 4: Decode QR code ---
qr_scaled = qr.resize((600, 600), Image.NEAREST)
results = decode(qr_scaled)
flag = results[0].data.decode()
print(f"Flag: {flag}")
```

## Tools Used

| Tool | Purpose |
|---|---|
| **ILSpy / ilspycmd** | .NET decompilation of `Assembly-CSharp.dll` |
| **UnityPy** | Unity asset bundle extraction (textures, sprites) |
| **Python (PIL/Pillow)** | Image manipulation and QR code assembly |
| **pyzbar** | QR code decoding |
| **Python (math.gcd)** | RSA factorization via pairwise GCD (for red herring #2) |

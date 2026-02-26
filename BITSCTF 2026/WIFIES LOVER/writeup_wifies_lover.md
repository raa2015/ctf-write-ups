# Wifies Lover #3 — BITSCTF 2026 Writeup

## Challenge Overview

| Field         | Value                                      |
| ------------- | ------------------------------------------ |
| **CTF**       | BITSCTF 2026                               |
| **Challenge** | Wifies Lover #3                            |
| **Category**  | OSINT / Misc                               |
| **Flag**      | `BITSCTF{L0_S13nt0_W1ls0n}`                |
| **Server**    | `minecraft.bitskrieg.in:25565` (Minecraft) |

### Challenge Description

> _The ocean was chosen because it looks infinite. Somewhere beyond the horizon lies a future drop location, not transmitted directly, only implied. The Resistance left behind a tool called CoolCommand, but its manual was lost during the evacuation. No instructions. No explanation. Only the name remains. Those who use it notice change, but not chaos. Don't Lose Hope, even wrong steps are steps towards a goal._

---

## TL;DR

1. Connect to a Minecraft server and reach **World 3** using `/guess` with coordinates from previous challenges
2. Discover that `/coolcommand` is **not registered** in Brigadier — the real command is `/cool_command` (with underscore)
3. **Bypass the command whitelist** using the fully-qualified plugin name: `/coolcommandplugin:cool_command`
4. Observe that CoolCommand teleports you through the ocean following a **convergent geometric spiral** (ratio = 0.93, constant angle)
5. **Mathematically calculate** the convergence point of the spiral using the geometric series formula
6. Submit the convergence point with `/guess 6765 16 2473` → **FLAG!**

---

## Detailed Solution

### Step 1 — Connecting to the Server

Since this is a Minecraft server challenge, I used **mineflayer** (a headless Node.js Minecraft bot library) to connect programmatically rather than through a regular game client. This allowed me to automate command execution, capture raw packet data, and scan the world efficiently.

```javascript
const mineflayer = require("mineflayer");
const bot = mineflayer.createBot({
  host: "minecraft.bitskrieg.in",
  port: 25565,
  username: "CTFPlayer_" + Math.floor(Math.random() * 9999),
  version: false, // auto-detect
});
```

On spawn, the bot landed at `(569.5, 59, 805.5)` in **adventure mode** in what turned out to be **World 1**.

### Step 2 — Command Discovery

My first task was to enumerate available commands. I quickly discovered the server enforces a strict whitelist:

```
> /help
"You cannot use that command. Only /coolcommand and /guess are allowed."

> /coolcommand
"Unknown or incomplete command, see below for error"
"coolcommand<--[HERE]"

> /guess
"Usage: /guess <x> <y> <z>"
```

The `/coolcommand` returned a vanilla Minecraft **Brigadier parser error**, meaning the parser couldn't find a command literally named `coolcommand`. This was the first hint that something was off.

### Step 3 — Tab Completion Reveals the Truth

Using mineflayer's `tabComplete` API, I queried the server for command suggestions:

```javascript
const matches = await bot.tabComplete("/cool");
// Result: [{"match":"cool_command"}, {"match":"coolcommandplugin:cool_command"}]
```

**The real command name is `cool_command` (with an underscore)**, registered by the plugin `coolcommandplugin`. But typing `/cool_command` directly was **blocked by the whitelist**:

```
> /cool_command
"You cannot use that command. Only /coolcommand and /guess are allowed."
```

I also discovered other plugins via tab completion:

- `guesslevels` — the `/guess` command plugin
- `multiverse-core` — multi-world management (3 worlds)

### Step 4 — Reaching World 3

Using coordinates provided from Wifies_Lover challenges #1 and #2:

```
/guess 522 60 752     → World 1 Flag: BITSCTF{G0D5p33d_F3ll0w_reb3l}
                        (Teleported to World 2)

/guess 106 70 -680    → World 2 Flag: BITSCTF{b34n135_b3tt3r_th4n_c4p5_n0_c4p}
                        (Teleported to World 3)
```

**World 3** spawned me at `(0, 16, 0)` — underwater in a flat, infinite ocean. The server automatically applied three effects: **Water Breathing**, **Night Vision**, and **Conduit Power**.

### Step 5 — The Whitelist Bypass

This is the core trick of the challenge. The whitelist checks whether the command string **starts with** `"coolcommand"`. I tested this hypothesis with the fully-qualified plugin command name:

```
/coolcommandplugin:cool_command
 ^^^^^^^^^^^^^^^
 starts with "coolcommand" → PASSES the whitelist!
```

And it worked! The key insight is that `coolcommandplugin:cool_command` starts with the characters "coolcommand", which satisfies the whitelist's prefix check, but is routed by Bukkit to the actual `cool_command` handler.

I confirmed this by also extracting the **Brigadier command tree** from the `declare_commands` packet:

```
Node 28: coolcommandplugin:cool_command [has_command=1, children=[45]]
Node 29: cool_command [has_command=1, children=[46]]
  └── Node 45/46: "args" (parser=GREEDY_PHRASE) [has_command=1]
```

The command accepts an optional greedy-phrase argument, but it's ignored — the behavior is the same with or without arguments.

### Step 6 — Understanding CoolCommand's Behavior

Running `/coolcommandplugin:cool_command` in World 3 **teleported the player to a new position** in the ocean, at Y=103-106 (above water surface). Each subsequent execution teleported further.

From the challenge description: _"Those who use it notice change, but not chaos"_ — the teleportation is **deterministic**, not random.

I logged the exact coordinates across 20 consecutive teleports:

| Step | X       | Z        |
| ---- | ------- | -------- |
| 0    | 8734.12 | -5202.23 |
| 1    | 8596.28 | -4664.97 |
| 2    | 8468.09 | -4165.31 |
| 3    | 8348.88 | -3700.63 |
| ...  | ...     | ...      |
| 19   | 7260.96 | 539.84   |

### Step 7 — Trajectory Analysis (The Key Insight)

Computing the deltas between consecutive positions revealed a remarkable pattern:

```
Step 1:  Δx=-137.8  Δz=537.3  dist=554.7  angle=104.4°
Step 2:  Δx=-128.2  Δz=499.7  dist=515.8  angle=104.4°
Step 3:  Δx=-119.2  Δz=464.7  dist=479.7  angle=104.4°
...
Step 19: Δx=-37.3   Δz=145.5  dist=150.2  angle=104.4°
```

Three critical observations:

1. **Constant angle**: Every step is at exactly **104.4°** — the direction never changes
2. **Constant ratio**: Each step is exactly **0.93×** the previous step's distance
3. **Shrinking steps**: Distance decays from 554.7 → 150.2 over 19 steps

This is a **convergent geometric series**! The trajectory spirals inward toward a fixed point. The challenge description's clue _"beyond the horizon lies a future drop location, not transmitted directly, only implied"_ now made perfect sense — the coordinates are **implied** by the convergent trajectory.

### Step 8 — Calculating the Convergence Point

For a geometric series with ratio `r = 0.93`, the sum of all remaining steps from the last known position is:

```
S = last_delta × r / (1 - r)
```

Where `r / (1 - r) = 0.93 / 0.07 ≈ 13.286`

```
Remaining ΔX = -37.33 × 0.93 / (1 - 0.93) = -495.97
Remaining ΔZ = 145.51 × 0.93 / (1 - 0.93) = 1933.25

Convergence X = 7260.96 + (-495.97) = 6764.99 ≈ 6765
Convergence Z = 539.84 + 1933.25 = 2473.09 ≈ 2473
```

To validate, I ran the same analysis on a completely separate trajectory from an earlier session:

| Run   | Convergence X | Convergence Z |
| ----- | ------------- | ------------- |
| Run 1 | 6776          | 2464          |
| Run 3 | 6765          | 2473          |

Both runs converge to approximately the **same point** (~6770, ~2468), confirming the convergence target is fixed.

### Step 9 — Getting the Flag

With X=6765 and Z=2473 calculated, and knowing World 3's sea floor is at Y=16, I submitted:

```
/guess 6765 16 2473
```

```
You found the flag for World3: BITSCTF{L0_S13nt0_W1ls0n}
```

🎉 **Flag: `BITSCTF{L0_S13nt0_W1ls0n}`**

Note: The Y coordinate is flexible — the flag also triggers with Y=63, Y=64, etc. The important coordinates are **X=6765** and **Z=2473**.

---

## Flag Analysis

`BITSCTF{L0_S13nt0_W1ls0n}` decodes from leet-speak to **"Lo Siento Wilson"** ("I'm Sorry, Wilson" in Spanish). This is a reference to the movie **Cast Away** (2000), where Tom Hanks' character is stranded in the ocean and forms an emotional bond with a volleyball named "Wilson." When Wilson floats away, he cries _"I'm sorry, Wilson!"_ — perfectly fitting the ocean theme of this challenge.

---

## Key Techniques Used

| Technique                     | Application                                           |
| ----------------------------- | ----------------------------------------------------- |
| **Headless Minecraft bot**    | Automated server interaction via mineflayer           |
| **Command enumeration**       | Tab completion to discover real command names         |
| **Whitelist bypass**          | Fully-qualified plugin name prefix collision          |
| **Brigadier packet analysis** | Extracted command tree from `declare_commands` packet |
| **Geometric series math**     | Calculated spiral convergence point                   |
| **Multi-run validation**      | Confirmed convergence from independent trajectories   |

---

## Tools

- **Node.js** + **mineflayer** — Headless Minecraft client
- **Custom scripts** — Trajectory logging, block scanning, convergence calculation
- All bot scripts available in the `mc-bot/` directory

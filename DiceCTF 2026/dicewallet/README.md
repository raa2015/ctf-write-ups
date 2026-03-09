# DiceWallet Package EN

This directory is a curated, self-contained English package of the `DiceWallet` exploit material.

## Recommended order

1. Read [`docs/FULL_WRITEUP_EN.md`](./docs/FULL_WRITEUP_EN.md)
2. Use [`docs/TOOL_GUIDE.md`](./docs/TOOL_GUIDE.md) to locate each script and artifact
3. Review `artifacts/logs/` and `artifacts/results/` as execution evidence

## Structure

- `docs/`: main package documentation.
- `exploits/`: payloads, generators, listeners, solvers, harnesses, and preserved PoCs.
- `artifacts/logs/`: revalidation notes and relevant execution logs.
- `artifacts/results/`: final extracted results.
- `data/`: the BIP39 wordlist used by the probes.
- `web_dicewallet/`: the minimum bot and extension source files cited by the writeup.

## Included

- full writeup in English
- solve scripts and revalidation tooling
- historical PoCs that were actually useful as references
- remote, local, and Serveo investigation logs
- final recovered words and positions

## Final result included

- `artifacts/results/mnemonic_final.txt`
- `artifacts/results/flag_final.txt`
- `artifacts/results/found_positions_indexed.jsonl`

## Intentionally excluded

- `serveraws.pem`
- `__pycache__/`
- temporary `scratch/` files
- noisy or sensitive logs that added no new evidence

## Note

The writeup links already point to relative paths inside this package, so it can be browsed independently from the original repository root.

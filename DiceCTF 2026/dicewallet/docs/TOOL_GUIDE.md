# Tool Guide

This guide summarizes what each important file in the package does and which phase it belongs to.

## Phase 1: pivot into `localhost:8080`

- [`../exploits/active/payload.html`](../exploits/active/payload.html): final race wrapper. It loads `z-<token>.js`, sends the `DICE_REQUEST` with `fn = "setTimeout"`, and navigates to `http://localhost:8080/admin/index.html`.
- [`../exploits/generators/stage1_wallet_probe.py`](../exploits/generators/stage1_wallet_probe.py): generates the second-stage script used to confirm `XSS`, `STATE`, `ACCTS`, and `STAGE1_OK`.
- [`../exploits/servers/exploit_server_final.py`](../exploits/servers/exploit_server_final.py): main HTTP harness. It serves payloads and records `/exfil/*`.
- [`../exploits/scripts/test_exploit.sh`](../exploits/scripts/test_exploit.sh): quick manual race validation helper.
- [`../exploits/research_html/exploit_race_final.html`](../exploits/research_html/exploit_race_final.html): preserved phase-1 PoC kept for reference.

## Phase 2: popup, STTF, and oracle

- [`../exploits/generators/STTF_payload.py`](../exploits/generators/STTF_payload.py): original payload generator used to split the BIP39 list into groups.
- [`../exploits/generators/position_subset_payload.py`](../exploits/generators/position_subset_payload.py): indexed group probes used in the final extraction flow.
- [`../exploits/generators/order_payload.py`](../exploits/generators/order_payload.py): `1. word`, `2. word`, etc. probes used for exact positions and negative controls.
- [`../exploits/listeners/oracle_listener_sni.py`](../exploits/listeners/oracle_listener_sni.py): TLS listener that extracts SNI from ClientHello packets.
- [`../exploits/solvers/solve_live_sni_indexed.py`](../exploits/solvers/solve_live_sni_indexed.py): final challenge solver.
- [`../exploits/solvers/solve_live_sni.py`](../exploits/solvers/solve_live_sni.py): earlier SNI-based variant.
- [`../exploits/solvers/solve_live_sttf.py`](../exploits/solvers/solve_live_sttf.py): earlier callback/STTF automation kept for comparison.

## Auxiliary harnesses and PoCs

- [`../exploits/servers/server.py`](../exploits/servers/server.py): early wrapper that served `z.js` through the original pivot.
- [`../exploits/research_html/exploit_export_meta.html`](../exploits/research_html/exploit_export_meta.html): positive `meta refresh` popup redirect PoC.
- [`../exploits/research_html/exploit_export_jsmeta.html`](../exploits/research_html/exploit_export_jsmeta.html): negative `javascript:` `meta refresh` PoC.

## Logs and evidence

- [`../artifacts/logs/live_revalidation_2026-03-09.md`](../artifacts/logs/live_revalidation_2026-03-09.md): remote revalidation against a live instance.
- [`../artifacts/logs/local_revalidation_2026-03-09.md`](../artifacts/logs/local_revalidation_2026-03-09.md): local revalidation against `http://localhost:8080`.
- [`../artifacts/logs/serveo_investigation_2026-03-09.md`](../artifacts/logs/serveo_investigation_2026-03-09.md): test of whether Serveo could replace the VPS.
- [`../artifacts/logs/live_sni_indexed_progress.log`](../artifacts/logs/live_sni_indexed_progress.log): progress from indexed solver runs.
- [`../artifacts/logs/live_sni_progress.log`](../artifacts/logs/live_sni_progress.log): progress from the earlier SNI solver.
- [`../artifacts/logs/live_sttf_progress.log`](../artifacts/logs/live_sttf_progress.log): progress from the earlier STTF/callback runner.

## Final results

- [`../artifacts/results/found_words_indexed.txt`](../artifacts/results/found_words_indexed.txt): the final 12 words in mnemonic order inside this curated package.
- [`../artifacts/results/found_positions_indexed.jsonl`](../artifacts/results/found_positions_indexed.jsonl): recovered final positions.
- [`../artifacts/results/mnemonic_final.txt`](../artifacts/results/mnemonic_final.txt): the full mnemonic on one line.
- [`../artifacts/results/flag_final.txt`](../artifacts/results/flag_final.txt): the validated final flag.

## Source files cited by the writeup

- [`../web_dicewallet/bot/server.js`](../web_dicewallet/bot/server.js)
- [`../web_dicewallet/challenge/src/background.js`](../web_dicewallet/challenge/src/background.js)
- [`../web_dicewallet/challenge/src/content.js`](../web_dicewallet/challenge/src/content.js)
- [`../web_dicewallet/challenge/src/inpage.js`](../web_dicewallet/challenge/src/inpage.js)
- [`../web_dicewallet/challenge/src/popup.js`](../web_dicewallet/challenge/src/popup.js)

The compiled extension bundle is also included in `../web_dicewallet/challenge/dist_ext/` in case you want to inspect the exact code used by the bot.

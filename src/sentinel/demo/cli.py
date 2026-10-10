"""`sentinel-demo` command line: narrated runs of the three demo scenarios against
a real, already-running Compose stack (`make up`). See `scenarios.py` for what each
one does and `client.py` for the shared HTTP driver also used by `tests/e2e/`.

sentinel-demo list                 describe the available scenarios
sentinel-demo run a|b|c            trigger a scenario and narrate it to resolution
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from sentinel.demo.client import DemoConfig, DemoStalledError, DemoTimeoutError, SentinelDemoClient
from sentinel.demo.scenarios import SCENARIOS, SERVICE


def _say(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _cmd_list(_: argparse.Namespace) -> int:
    for s in SCENARIOS.values():
        print(f"\n{s.id}: {s.title}")
        print(f"   {s.description}")
        print(f"   expects: {s.expected_alert} -> {s.expected_runbook}")
    print()
    return 0


async def _run(args: argparse.Namespace) -> int:
    scenario = SCENARIOS[args.scenario]
    config = DemoConfig.from_secrets(
        Path(args.secrets_dir), sentinel_url=args.sentinel_url, actuator_url=args.actuator_url
    )
    async with SentinelDemoClient(config) as client:
        _say(f"Scenario {scenario.id} ({scenario.title}): {scenario.description}")
        started_at = datetime.now(UTC)
        await scenario.trigger(client)
        _say(f"Fault triggered. Waiting for {scenario.expected_alert} to open an incident...")

        try:
            incident = await client.wait_for_incident(
                SERVICE, opened_after=started_at, timeout_s=args.timeout
            )
            ref = incident["short_id"]
            _say(f"Incident {ref} opened: {incident['title']!r} (severity={incident['severity']})")

            investigation = await client.wait_for_investigation(ref, timeout_s=args.timeout)
            if investigation["status"] == "failed":
                _say(f"Investigation FAILED: {investigation.get('error')}")
                return 1
            root = investigation["hypotheses"][0] if investigation["hypotheses"] else None
            if root:
                _say(
                    f"Investigation complete ({investigation['label']}): "
                    f"{root['statement']!r} (confidence {root['confidence']:.2f})"
                )

            action = await client.wait_for_proposed_action(ref, timeout_s=args.timeout)
            _say(f"Action proposed: {action['runbook_id']} (status={action['status']})")

            if not args.approve:
                _say(
                    f"--no-approve given; stopping here. Approve it yourself: "
                    f"POST /api/v1/actions/{action['id']}/approve"
                )
                return 0

            if action["status"] == "pending_approval":
                await client.approve(action["id"], "approved by sentinel-demo")
                _say("Action approved.")

            resolved = await client.wait_for_resolution(
                ref, timeout_s=args.timeout, on_status=lambda s: _say(f"Incident status: {s}")
            )
            verified = resolved.get("resolved_verified")
            _say(
                f"Incident {ref} {resolved['status']} "
                f"(resolved_verified={verified}) — scenario complete."
            )
            return 0 if resolved["status"] == "resolved" and verified else 1
        except DemoStalledError as exc:
            _say(f"STALLED: {exc}")
            return 1
        except DemoTimeoutError as exc:
            _say(f"TIMED OUT: {exc}")
            return 1


def _cmd_run(args: argparse.Namespace) -> int:
    return asyncio.run(_run(args))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-demo")
    parser.add_argument("--sentinel-url", default="http://127.0.0.1:8080")
    parser.add_argument("--actuator-url", default="http://127.0.0.1:8085")
    parser.add_argument("--secrets-dir", default="secrets")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="describe the available scenarios").set_defaults(fn=_cmd_list)

    run = sub.add_parser("run", help="trigger a scenario and narrate it to resolution")
    run.add_argument("scenario", choices=sorted(SCENARIOS))
    run.add_argument("--timeout", type=float, default=180.0, help="seconds per wait step")
    approve = run.add_mutually_exclusive_group()
    approve.add_argument("--approve", dest="approve", action="store_true", default=True)
    approve.add_argument(
        "--no-approve",
        dest="approve",
        action="store_false",
        help="stop once an action is proposed, without approving it",
    )
    run.set_defaults(fn=_cmd_run)

    args = parser.parse_args(argv)
    result: int = args.fn(args)
    return result


if __name__ == "__main__":
    sys.exit(main())

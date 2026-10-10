# Recording a demo

Two things are worth recording, and they're independent: the narrated terminal run
(`sentinel-demo`) and the web UI. Neither needs editing — `sentinel-demo` already
prints a clean, timestamped narration intended to be watched as-is.

## Terminal: `sentinel-demo` via asciinema

```bash
make e2e-up                    # stack up, SENTINEL_EXECUTION_MODE=live (a real fix, not a no-op)
./scripts/record-demo.sh b     # scenario a, b, or c — see `sentinel-demo list`
```

This wraps `asciinema rec -c "uv run sentinel-demo run <scenario>"`. It checks
`sentinel-api` is reachable first and fails fast with a clear message if the stack
isn't up. Install asciinema first if you don't have it: `brew install asciinema`
(macOS) or `pipx install asciinema` (Linux).

Output is a `.cast` file (JSON, text — small, diff-able, safe to commit if you want
a fixture recording). Play it back locally with `asciinema play <file>.cast`, or
convert to a GIF for embedding in docs/README with
[`agg`](https://github.com/asciinema/agg) (`brew install agg` or
`cargo install --locked agg`):

```bash
agg demo-b-20261010-120000.cast demo-b.gif
```

`asciinema upload <file>.cast` publishes to asciinema.org and gives you a shareable
link and an embeddable player, if you don't want to self-host the recording.

Pick the scenario order by what you want to show: scenario B (bad release → auto
rollback) is the most legible single-scenario demo for someone unfamiliar with the
project. Run all three back-to-back only on a fresh stack (`make clean && make
e2e-up`) — see `docs/troubleshooting.md`'s entry on scenario C for why order matters
when chaining them on a stack that's already run others recently.

## Browser: the web UI

The CLI only narrates the backend; it never opens a browser. For a demo that also
shows the UI (Phase 7 — incident list/detail, the approval page, postmortems), run
the scenario in one terminal and drive the browser in parallel:

```bash
./scripts/record-demo.sh b &      # or run sentinel-demo directly without recording
open http://127.0.0.1:8080/login  # macOS; xdg-open on Linux
```

Log in with an API token (`cat secrets/sentinel_admin_token`, or
`make token NAME=you ROLE=approver` for your own). Useful beats to hit while the
scenario runs: the incident appearing on `/` moments after the fault is injected,
the Observations vs. AI Hypotheses split on `/incidents/{ref}` once evidence and
the investigation land, the DRY-RUN/LIVE banner (confirms this is a real fix), the
approval page's runbook-content check, and the postmortem generated afterward
(`/incidents/{ref}/postmortem`, click "Generate draft").

For screen capture: QuickTime Player's "New Screen Recording" (macOS, free, no
install) or OBS Studio (cross-platform) both work fine — there's nothing
Sentinel-specific to the capture step itself.

## A clean take

Scenario timing is compressed for exactly this reason (D10 in `docs/architecture.md`)
— a full scenario runs in a few minutes, not the tens of minutes a real incident's
timers would take. Still, for the cleanest recording:

- Start from a quiet stack: `make clean && make e2e-up` if you've been testing
  recently, rather than reusing a stack scenario B or C already ran on (see the
  troubleshooting entry above).
- `sentinel-demo run <scenario>` without `--no-approve` goes all the way to verified
  recovery unattended — good for a hands-off recording. Add `--no-approve` if you
  want to narrate the approval step yourself in the browser instead of having the
  CLI approve it automatically.
- `sentinel-demo` exits non-zero on timeout or a stalled remediation (see
  `DemoStalledError`/`DemoTimeoutError` in `sentinel.demo.client`) — if a take ends
  that way, it's worth checking *why* rather than just re-recording; it's the same
  signal an on-call engineer would get.

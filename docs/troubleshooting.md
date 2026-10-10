# Troubleshooting

Each entry here is a problem actually hit while building Sentinel, with the confirmed fix.

## `docker: unknown command: docker compose`
On Homebrew/Colima installs, Compose is often only the standalone binary. The Makefile
uses `docker-compose` (override with `make COMPOSE="docker compose -f deploy/compose/docker-compose.yml" ...`).

## Socket proxies are unhealthy / `permission denied` on `/var/run/docker.sock`
The proxies run as `65534:991`, where `991` is the Docker socket's group **inside the
Colima VM**. If your VM uses a different group ID, find it and update `user:` for
both `socket-proxy-*` services in `deploy/compose/docker-compose.yml`:
```bash
docker run --rm -v /var/run/docker.sock:/s:ro --entrypoint sh prom/prometheus:v3.13.4 -c 'stat -c %g /s'
```

## Loki has no logs; Alloy logs `error while computing network labels: ... Forbidden`
Alloy's Docker discovery also calls `GET /networks`. That path must be in
`socket-proxy-ro`'s `-allowGET` regex (it is in the shipped config). Blocked
requests show in `make logs SERVICE=socket-proxy-ro` as `blocked request ... URL=...`.
That is the quickest way to debug any proxy denial.

## Actuator returns 409 `image ... is not available locally`
The shop-api release images are built locally, never pulled. Run `make images`.

## The actuator gets `403 sentinel docker-guard: ...`
This is the admission controller refusing a request, which is intended behaviour.
The message names the violated rule. Check `make logs SERVICE=docker-guard`.

## `docker system df` fails with `rw layer snapshot not found`
This is unrelated to Sentinel: the daemon has dead containers left over from another
project. `docker ps`, which Sentinel uses, still works. Sentinel never touches
containers it doesn't manage, and docker-guard enforces that.

## Memory pressure is slower to build than requested
Memory chaos allocates in 0.25s ticks on the service's event loop. Under the
0.5-CPU quota with live traffic, the observed rate is about 1.5–2 MB/s even when
4 MB/s is requested. The alert still fires; it just takes about 2 minutes.

## macOS: `timeout: command not found`
macOS has no GNU `timeout`. The scripts here avoid it; use `gtimeout` (coreutils) if needed.

## High memory use / swapping on an 8 GB Mac
The Sentinel stack measured about 0.8 GB in use (limits total about 3.3 GB). Other projects' containers in the same Colima VM
and a 7B Ollama model compete for the same RAM. See `docs/architecture.md` §9.

## Grafana: Loki datasource says "Plugin not registered"
Grafana 13 ships Loki as a decoupled bundled plugin. At startup its background
installer tries to relocate it, which fails on a read-only root filesystem
(`unlinkat .../plugins-bundled/loki: read-only file system` in the Grafana logs).
The stack sets `GF_PLUGINS_PREINSTALL_DISABLED=true`, so Grafana uses the bundled copy.
This also means Grafana makes no plugin downloads at runtime.

## Loki queries time out over long windows
`{service="x"} | json | level=~"error"` makes Loki parse every line; over 2 hours at
10 rps it timed out. Sentinel selects on the indexed `level` stream label that Alloy
promotes (`{service="x", level=~"error|critical"}`), which returns in about 1–6 seconds.
The worker's Loki timeout is `SENTINEL_LOKI_TIMEOUT_S` (default 20s).

## An incident shows no evidence
Check `make logs SERVICE=sentinel-worker` and the `sentinel_jobs` metric. Evidence is
collected about 10 seconds after an incident opens. `POST /api/v1/incidents/<id>/evidence/refresh`
(responder) queues another collection.

## Ollama investigations are extremely slow or time out (8 GB Macs)
Measured on an Apple M1 with 8 GB of unified memory, running Colima (8 GiB VM) and another
project's containers at the same time: `qwen2.5-coder:7b` loaded in 79s, processed the prompt
at 9 tokens/s and generated at 5 tokens/s (typical for this chip is about 100+ and 15-20).
A ~2,700-token investigation therefore took about 10 minutes, and the memory starvation also
degraded the stack (Sentinel correctly opened incidents for it).

**Fix applied (2026-10-09): the default Ollama model is now `qwen2.5-coder:3b`**, same
family, ~1.9 GB on disk vs 4.7 GB. On the same host: load 11s, prompt eval 90 tok/s,
generation 41 tok/s, fully GPU-offloaded at 2.2 GB. A full investigation (same scenario)
took **40 seconds** and correctly cited its evidence and recommended the right rollback —
no retries needed. Install it with `ollama pull qwen2.5-coder:3b` (already the shipped
default; override with `SENTINEL_OLLAMA_MODEL` to use something else, including the 7B).

Even at 3B, running the model alongside the whole stack can still briefly starve Postgres
on an 8 GB host (a crash-restart that self-heals via WAL replay in ~20s, with one or two
transient scrape-gap incidents). If that's not acceptable, or you want to go even lighter:
- Use the default `mock` provider (`SENTINEL_INVESTIGATION_PROVIDER=mock`) — no model needed.
- Free memory: stop other containers, or give Colima less memory (`colima stop && colima start --memory 4`).
- Use a still smaller model (e.g. a 1.5B), or quit Ollama between runs (`keep_alive: 2m` already unloads it quickly).
- For a one-off run, raise `SENTINEL_OLLAMA_TIMEOUT_S` / `SENTINEL_INVESTIGATION_TIMEOUT_S` (max 900).

## Containers can't reach Ollama
Ollama should stay bound to `127.0.0.1` (don't set `OLLAMA_HOST=0.0.0.0`; that exposes it to
your network). On Colima and Docker Desktop, containers reach the host loopback via
`host.docker.internal`. Check with:
`docker exec sentinel-sentinel-worker-1 python -c "import urllib.request;print(urllib.request.urlopen('http://host.docker.internal:11434/api/tags').read()[:100])"`.
On a plain Linux Docker Engine, set `SENTINEL_OLLAMA_URL` to an address Ollama listens on.

## Evidence collection fails with `invalid input syntax for type json: Token "NaN" is invalid`
Prometheus returns the literal `"NaN"` (or `"+Inf"`/`"-Inf"`) for a sample with no real
data behind it — most often `histogram_quantile` over a bucket with too few points.
Python's `json` module happily serialises `float('nan')` back out as the bare token
`NaN`, which is valid to *that* module but not standard JSON; Postgres's stricter JSON
parser rejects it outright, failing evidence storage. Fixed in `evidence/clients.py`:
non-finite points are dropped when a metric response is parsed, before they can reach
storage. If you see this on an older build, update; there is no workaround short of that.

## A verification check always reads "no data" / recovery never verifies
If `replicas_ready_ratio` (or any check dividing two metrics) always shows no data,
suspect a Prometheus vector-matching mismatch: dividing a recording rule's output
(label set reduced by its `by (...)`) against a raw scrape (which still carries
`job`/`instance`) needs an explicit `on(service)` — Prometheus's default one-to-one
match requires *identical* label sets and otherwise silently returns nothing, for
*every* sample, not just an occasional one. This exact bug shipped once in
`remediation/verifier.py` and was fixed with `on(service)`; if you add a new
verification signal that divides metrics from different sources, check its rendered
query directly against `/api/v1/query` before trusting it in a runbook.

## `sentinel-demo` scenario B/C fails with `httpx.ReadTimeout` or `RemoteProtocolError`
A real container replace with health checks (what a deploy/restart runbook actually
does) measured ~11s for a two-replica rolling replace on a loaded host — too slow for
a naive 10s HTTP client timeout, even though the actuator finishes the work fine. The
demo client (`sentinel.demo.client.SentinelDemoClient`) now uses 60s for actuator
calls and 30s for the Sentinel API. If you hit this writing your own tooling against
the actuator or Sentinel API, size the client timeout for container lifecycle
operations, not request/response latency.

## `sentinel-demo run <scenario>` times out waiting for "a new shop-api incident"
Incidents group by `environment/service`, not by alertname. If a previous scenario's
incident is still `resolved` (not yet `closed`), a fresh alert within the reopen
window (`reopen_window_s`, default 600s) *reopens* that old incident instead of
opening a new one — so `wait_for_incident`'s `opened_at >= started_at` check never
matches. `sentinel.demo.scenarios._reset_baseline` resolves and closes every
not-yet-`closed` incident for the service before triggering the next scenario
(`IncidentService._recently_resolved` matches on `status == resolved` alone, so
`active=True` filtering alone is not enough — a `resolved` incident is still active
for reopen purposes even though it isn't "active" in the UI/API sense).

## A scenario recommends the wrong runbook, or rolls back without fixing anything, when run shortly after another scenario
Two distinct causes, one fixed in code, one inherent to time-windowed evidence —
both stem from evidence correlation looking back a full hour (`CHANGE_LOOKBACK` in
`evidence/collector.py`), which is the *correct* design for real incidents (a
deployment an hour ago can still be the cause) but collides with synthetic fault
injection run far closer together than any real incident history would be.

**Cross-alert-type (e.g. scenario A gets a `rollback-deployment` recommendation for
a pure memory-pressure incident): this was a real bug, fixed.** A recent deployment
from a *different* scenario could outscore an incident's own alert type purely on
recency, even though `rollback-deployment` doesn't list that alert
(`ShopApiMemoryPressure`/`ShopApiHighCPU`) in its own `applies_to_alerts` at all. This
reproduced even on an otherwise-fresh stack, minutes after a single prior deployment
— not just on a long-lived, reused one. Fixed in `src/sentinel/investigation/providers.py`
(`MockProvider` now gates the correlation branch on the candidate runbook's
`applies_to_alerts`); if you're on an older build, update.

**Same-alert-type (scenario C recommends `restart-service` instead of
`rollback-deployment`, or rolls back to the wrong historical deployment and
verification then correctly fails): inherent, not a bug, still possible.** Scenario
C's own signal is intrinsically weak even in isolation: a crash-loop (`POOL_SIZE=0`)
never completes a request, so there is no "5xx response" metric to attribute to it at
all, and very few log lines get written before each restart (measured: ~0.435 against
the mock's 0.6 threshold, even with no other scenario having run at all). Both
`ShopApiCrashLooping` and `ShopApiHighErrorBurnRate` are in `rollback-deployment`'s
`applies_to_alerts`, so the fix above doesn't separate them — a stale scenario-B
deployment still within the lookback window can legitimately outscore scenario C's
own weak signal. This is why `tests/e2e/test_scenarios.py` runs scenario C first. If
you hit this interactively, either start from a fresh stack (`make clean && make
e2e-up`) before running scenario C, or wait a few minutes for the competing
deployment's `time_factor` to decay (roughly 10 minutes per half-life at this
evidence window's time constant) before retrying it.

## Chaos memory fault takes much longer than expected to trip `ShopApiMemoryPressure`
The chaos allocator's async ticks compete with real request traffic (loadgen) and
whatever else is running on the host; a live run on a loaded 8 GB Mac measured the
allocation rate falling well behind the fault's nominal `rate_mb_s`. The demo client
defaults to a more aggressive `rate_mb_s=10.0` (vs. the demo-app's own internal
default of 2.0) specifically to keep the alert's `for: 30s` window reachable within a
reasonable demo timeout even under contention; pass a higher value still if your host
is more loaded than that.

# Igropyr benchmark harness

[中文说明](README.zh-CN.md)

The benchmark harness compares two clean project copies whose directory name
is `igropyr`. It never writes build artifacts into the development checkout.

```sh
RUNS=7 WARMUPS=2 MODE=express-pooled \
  ./candidate/igropyr/bench/run-ab.sh \
  /tmp/baseline/igropyr /tmp/candidate/igropyr compiled
```

The default suite alternates baseline and candidate runs for:

- `ab -k -n 300000 -c 500` (primary pooled keep-alive gate)
- `ab -n 10000 -c 50`
- `ab -n 50000 -c 500`
- `ab -k -n 100000 -c 500`
- `ab -n 100000 -c 1000`

Results and server/build logs are written under `/tmp/igropyr-bench-*` unless
`OUT_DIR` is provided. `summary.csv` reports median throughput, coefficient of
variation, and median allocated bytes per completed request. Raw CSV rows also
include GC CPU/real time and bytes scanned, alongside total CPU, RSS and GC
count. The run fails when
either variant has CV above 5%, primary throughput gain is below 8%, primary
allocation reduction is below 20%, or any scenario regresses by more than 5%.
Set `SKIP_GATE=1` only for harness smoke tests.

Every measured run starts a fresh server, sends 20,000 keep-alive requests to
that exact process, then resets metrics before the scenario. Override this with
`RUN_WARMUP_REQUESTS`; use `0` only when checking the harness itself.
Measured runs increment the listen port from `PORT` so repeated new-connection
scenarios do not share one large TIME_WAIT four-tuple population. The server
continues to bind `0.0.0.0`.
After each baseline/candidate pair, new-connection scenarios also wait 30
seconds (twice the default macOS TCP MSL) for the small ephemeral-port pool to
recover. Override with `NEW_CONN_COOLDOWN`; setting it to `0` is suitable for
quick smoke tests, not formal stability measurements.

Use `source` instead of `compiled` for the source-loaded confirmation run.
For Scheme profiling, run `bench/build-profile.ss` in a temporary copy, start
`bench/server.sc`, execute a fixed load, and request `/__bench/profile`.
The response is the generated profile index path; Chez writes one HTML file per
instrumented source next to it.
On macOS, sample native stacks during the load with:

```sh
sample SERVER_PID 10 -file /tmp/igropyr-native-sample.txt
```

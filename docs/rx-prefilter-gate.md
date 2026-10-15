# SecRxPreFilter gate

`SecRxPreFilter On` makes the `@rx` operator skip a regular expression when a literal its
pattern needs is missing from the input. It is experimental in Coraza. A bug in it hides a
detection without any error: the rule simply does not match. The gate proves, for one ruleset
and one build of this fork, that `On` and `Off` give the same answer. Enable `On` on a
server only when the gate passed for the ruleset and the fork tag that server runs.

## Running it

```bash
bash scripts/rx-prefilter-gate.sh --rules <dir with the ruleset's *.conf>
bash scripts/rx-prefilter-gate.sh --download                 # latest Imunify360 coraza archive
bash scripts/rx-prefilter-gate.sh --download --mode full     # adds the end-to-end replay
```

It needs Go and a checkout of the fork at the tag the product pins. Exit status 0 means
`On` and `Off` agree; 1 means they disagree or a check could not run. `build/rx-prefilter-gate/summary.txt`
holds the short result and ends with `RESULT: PASS` or `RESULT: FAIL`.

| Mode | What it does | Time |
| --- | --- | --- |
| `pattern` | Takes every `@rx` pattern of the ruleset, builds the operator with and without the prefilter, feeds both inputs generated from the pattern itself and requires the same answer. | seconds (7 s for 1,426 patterns and 3 million inputs), plus compiling |
| `full` | `pattern`, then replays the CRS regression corpus, each payload carried six ways (as written, query string, urlencoded form, JSON, a padded 28 KB body, echoed in the response), through the bundled CRS and through the ruleset, and compares the matched rule ids and the interruption of every transaction. | about 10 min (22,427 requests, three configurations) |

The ruleset build should run `pattern` on every candidate ruleset: it is cheap enough to run
on each daily rule edit, before the ruleset is published. The workflow `rx-prefilter-gate.yml` runs `full` on every `v*-cl*`
tag and can be started by hand.

## What it does not cover

Both modes use generated and corpus inputs, not production traffic. They do not replace
replaying real blocked requests from audit logs, and they say nothing about performance. A
pattern the generator cannot build matching inputs for is compared on fewer inputs; the
`inputs compared, N of them matched by the regex` line shows how many it could.

## Knobs

`CORAZA_PREFILTER_SAMPLES` (inputs per pattern, default 300), `MIN_PATTERNS` (fail if fewer
patterns than this are found, default 100), `OUT` (output directory), `RULESET_INDEX` (the
`description.json` that `--download` reads). `--limit N` shortens the replay to the first N
corpus requests for a smoke run.

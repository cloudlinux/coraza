#!/usr/bin/env bash
# Fails when SecRxPreFilter On and Off disagree on a ruleset. See docs/rx-prefilter-gate.md.
#
#   scripts/rx-prefilter-gate.sh --rules <dir with *.conf>        # pattern check only (seconds)
#   scripts/rx-prefilter-gate.sh --download                       # fetch the latest Imunify360 coraza archive first
#   scripts/rx-prefilter-gate.sh --rules <dir> --mode full        # pattern check, then the end-to-end replay
#   scripts/rx-prefilter-gate.sh --rules <dir> --mode full --limit 200   # smoke run of the replay
#
# Modes:
#   pattern  every @rx pattern of the ruleset, built with and without the prefilter, fed inputs
#            generated from the pattern itself (internal/operators, TestRxPrefilterAgainstLabRuleset)
#   full     pattern, then the CRS regression corpus carried six ways through the bundled CRS and
#            through the ruleset, Off against On (testing/coreruleset, TestRxPreFilterParity;
#            about 10 minutes)
#
# Exit status: 0 when Off and On agree everywhere, 1 on any disagreement or when a check could
# not run, 2 on bad usage. Output goes to $OUT (default build/rx-prefilter-gate); summary.txt there
# is the short version and ends with RESULT: PASS or RESULT: FAIL.
#
# Environment:
#   OUT                              output directory
#   CORAZA_PREFILTER_SAMPLES         generated inputs per pattern (default 300)
#   MIN_PATTERNS                     fail if the ruleset yields fewer @rx patterns (default 100), so
#                                    a ruleset that failed to unpack cannot pass by being empty
#   RULESET_INDEX                    description.json that --download reads
set -uo pipefail

MODE=pattern
RULES=""
LIMIT=""
DOWNLOAD=0
while [ $# -gt 0 ]; do
  case "$1" in
    --rules)    RULES="${2:-}"; shift 2 ;;
    --mode)     MODE="${2:-}"; shift 2 ;;
    --limit)    LIMIT="${2:-}"; shift 2 ;;
    --download) DOWNLOAD=1; shift ;;
    -h|--help)  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$MODE" in pattern|full) ;; *) echo "--mode must be pattern or full" >&2; exit 2 ;; esac
if [ "$DOWNLOAD" = 0 ] && [ -z "$RULES" ]; then echo "give --rules <dir> or --download" >&2; exit 2; fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
OUT="${OUT:-$ROOT/build/rx-prefilter-gate}"
case "$OUT" in /*) ;; *) OUT="$ROOT/$OUT" ;; esac
SAMPLES="${CORAZA_PREFILTER_SAMPLES:-300}"
MIN_PATTERNS="${MIN_PATTERNS:-100}"
INDEX="${RULESET_INDEX:-https://files.imunify360.com/static/modsec/v2/description.json}"
mkdir -p "$OUT"
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"
say() { echo "$*" | tee -a "$SUMMARY"; }

fail=0

# ---- the ruleset ---------------------------------------------------------------
if [ "$DOWNLOAD" = 1 ]; then
  DESC="$OUT/description.json"
  curl -fsS -L --compressed "$INDEX" -o "$DESC" || { say "could not fetch $INDEX"; say "RESULT: FAIL"; exit 1; }
  LINE="$(awk '
    $1 ~ /md5sum/{ hs=$2; next };
    $1 ~ /url/ && $2 ~ /coraza/ && $2 ~ /full/ && $2 !~ /meta|modsec3/ {
      gsub(/[",]/,"",hs); gsub(/[",]/,"",$2); print hs, $2 }' "$DESC" | head -n1)"
  [ -n "$LINE" ] || { say "no coraza full archive in $INDEX"; say "RESULT: FAIL"; exit 1; }
  WANT="${LINE%% *}"; URL="${LINE##* }"
  ZIP="$OUT/$(basename "$URL")"
  curl -fsS -L --compressed "$URL" -o "$ZIP" || { say "download of $URL failed"; say "RESULT: FAIL"; exit 1; }
  GOT="$(md5sum "$ZIP" | cut -d' ' -f1)"
  [ "$GOT" = "$WANT" ] || { say "md5 mismatch for $URL (want $WANT, got $GOT)"; say "RESULT: FAIL"; exit 1; }
  RULES="$OUT/ruleset"
  rm -rf "$RULES"; mkdir -p "$RULES"
  unzip -q -j "$ZIP" -d "$RULES" || { say "unzip failed"; say "RESULT: FAIL"; exit 1; }
  say "archive: $URL (md5 $GOT)"
fi
RULES="$(cd "$RULES" 2>/dev/null && pwd)" || { say "no such directory: $RULES"; say "RESULT: FAIL"; exit 1; }
[ -n "$(ls "$RULES"/*.conf 2>/dev/null)" ] || { say "no *.conf in $RULES"; say "RESULT: FAIL"; exit 1; }
say "ruleset: $RULES   version: $(head -n1 "$RULES/VERSION" 2>/dev/null || echo unknown)   conf files: $(ls "$RULES"/*.conf | wc -l)   SecRule lines: $(cat "$RULES"/*.conf | grep -c '^[[:space:]]*SecRule')"
say "fork:    $(git log -1 --format='%h %s' 2>/dev/null)   $(git describe --tags --always 2>/dev/null)   mode: $MODE"
say "go:      $(go version)"

# ---- 1. every @rx pattern ------------------------------------------------------
say ""
say "== pattern check (every @rx pattern, prefilter on against off)"
CORAZA_PREFILTER_RULES="$RULES" CORAZA_PREFILTER_SAMPLES="$SAMPLES" \
  go test ./internal/operators/ -run '^TestRxPrefilterAgainstLabRuleset$' -count=1 -v -timeout 0 >"$OUT/pattern.log" 2>&1
rc=$?
grep -E 'distinct @rx|compiled|compared' "$OUT/pattern.log" | sed 's/^ *//' | tee -a "$SUMMARY"
PATTERNS="$(sed -n 's/.*: \([0-9][0-9]*\) distinct @rx patterns.*/\1/p' "$OUT/pattern.log" | head -n1)"
if [ "$rc" != 0 ]; then
  say "pattern check FAILED (exit $rc); disagreeing patterns:"
  grep 'prefilter changed' "$OUT/pattern.log" | cut -c1-400 | head -40 | tee -a "$SUMMARY"
  grep -q 'prefilter changed' "$OUT/pattern.log" || tail -n 30 "$OUT/pattern.log" | tee -a "$SUMMARY"
  fail=1
elif [ -z "$PATTERNS" ] || [ "$PATTERNS" -lt "$MIN_PATTERNS" ]; then
  say "pattern check found ${PATTERNS:-no} @rx patterns, fewer than MIN_PATTERNS=$MIN_PATTERNS: the ruleset did not load as expected"
  fail=1
else
  say "pattern check: PASS"
fi

# ---- 2. end to end -------------------------------------------------------------
if [ "$MODE" = full ]; then
  say ""
  say "== end-to-end replay (CRS regression corpus, six carriers, prefilter off against on)"
  CORAZA_RX_PARITY=1 CORAZA_RX_PARITY_RULES="$RULES" CORAZA_RX_PARITY_LIMIT="$LIMIT" \
  CORAZA_RX_PARITY_REPORT="$OUT/replay-report.txt" \
    go test ./testing/coreruleset/ -run '^TestRxPreFilterParity$' -count=1 -v -timeout 0 >"$OUT/replay.log" 2>&1
  rc=$?
  if [ -s "$OUT/replay-report.txt" ]; then
    grep -E '^==|requests run|requests that differ' "$OUT/replay-report.txt" | sed 's/^ *//' | tee -a "$SUMMARY"
  fi
  if [ "$rc" != 0 ]; then
    say "end-to-end replay FAILED (exit $rc); see $OUT/replay-report.txt and replay.log"
    [ -s "$OUT/replay-report.txt" ] || tail -n 30 "$OUT/replay.log" | tee -a "$SUMMARY"
    fail=1
  else
    say "end-to-end replay: PASS"
  fi
fi

say ""
if [ "$fail" = 0 ]; then say "RESULT: PASS (prefilter on and off agree)"; else say "RESULT: FAIL (do not enable SecRxPreFilter On with this ruleset and fork build)"; fi
echo "full logs in $OUT"
exit "$fail"

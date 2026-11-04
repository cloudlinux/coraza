# ADR-0065: Request body arguments are counted like ModSecurity v2

- **Status:** proposed
- **Date:** 2026-11-04
- **Version:** unreleased (post-v3.8.1-cl10)
- **PR:** [#35](https://github.com/cloudlinux/coraza/pull/35)
- **Issue(s):** No linked issue; fork tracking ticket DEF-57965
- **Deciders:** Gabriel Grigoras (CloudLinux)
- **Category:** Parity (ModSecurity v2 argument counting)

## Context and Problem

Run through ModSecurity 2.9.7 (the Debian 12 package) and through Coraza, the same
JSON bodies gave different `ARGS` and a different `REQBODY_ERROR` in three ways:

- ModSecurity charges JSON values against `SecArgumentsLimit` together with the
  arguments the request already holds. With 10 query arguments and 995 JSON values
  it keeps 1000 arguments and sets `REQBODY_ERROR`; Coraza kept 1006 and set nothing.
- Coraza adds an entry holding the length of every non-empty array; ModSecurity adds
  none. A body of 999 one-element arrays gave 999 arguments in ModSecurity and 1998
  in Coraza, and every rule that inspects `ARGS` ran over all of them.
- ModSecurity trips the limit only when it is about to add a value, then stops
  parsing. Coraza tripped on the next key even when it led only to empty
  containers, and after a trip still scanned the rest of the body twice (nesting
  check and validation).

The first difference is not specific to JSON. ModSecurity keeps one argument table
(`msr->arguments`) for the query string, urlencoded bodies, multipart text fields
and JSON, and checks the limit against it in `add_argument` (`msc_parsers.c`) and
in the JSON parser (`msc_json.c`). Coraza's urlencoded and multipart processors
counted their own arguments from zero. XML fills no `ARGS` in ModSecurity v2.

## Decision Drivers

- The same body should give the same `ARGS`, and the same `REQBODY_ERROR`, under
  both engines, so one ruleset behaves the same on either.
- Rules should not run over entries ModSecurity never produces.
- No work for a body past the point where its arguments stop being stored.

## Considered Options

- Keep Coraza's behaviour.
- Count length entries against the limit but keep them.
- Align the JSON processor only: share the limit with `ARGS_GET` and `ARGS_PATH`,
  drop the length entries, trip only when a value would be added and stop the walk
  there.
- The same, with the shared limit applied to every processor that fills `ARGS_POST`.

## Decision Outcome

Chosen: **the JSON alignment, with the shared limit in every processor that fills
`ARGS_POST`**, because it is the only option under which both engines store the
same arguments and raise the same error for every body type. Keeping length
entries, counted or not, still shows rules values ModSecurity does not have.

The transaction passes the number of arguments it already holds in a new
experimental field, `plugintypes.BodyProcessorOptions.ArgumentsUsed`. The JSON,
urlencoded and multipart processors start their count there. XML keeps its own
scaled budget: it fills `REQUEST_XML`, not `ARGS`, in both engines. Multipart still
charges a file part one member, which ModSecurity does not.

## Technical Discussion

No substantive technical discussion recorded that can be quoted here: the review
took place on the fork PR, and quotes need a corazawaf/coraza permalink. The
review asked why only JSON shared the limit, since ModSecurity keeps one argument
table for every body processor. That widened the decision from JSON alone to
urlencoded and multipart.

## Participants

- Gabriel Grigoras (CloudLinux): author
- Artem Murashkin (CloudLinux): reviewer

## Consequences

- **Positive:** `ARGS` counts and `REQBODY_ERROR` for JSON match ModSecurity 2.9.7
  on every case compared. Urlencoded and multipart share the limit the way
  ModSecurity's source does. Bodies with many arrays carry up to half the
  arguments: the 999-array body went from about 142 ms to 61 ms of CPU through a
  production-size ruleset. The length entries that grew with nesting depth
  (GHSA-6r3q-mjv7-xr8m) no longer exist.
- **Negative / follow-up:** a rule that read an array's length from `ARGS`
  (`ARGS:json.items` holding `3`) no longer matches, and `&ARGS` is lower for bodies
  with arrays. A JSON, urlencoded or multipart body can now trip the limit because
  of query arguments, as in ModSecurity. This deviates from upstream Coraza, so
  later syncs touching `json.go`, `urlencoded.go` or `multipart.go` in
  `internal/bodyprocessors` need care.

## References

- PR: https://github.com/cloudlinux/coraza/pull/35
- Related ADRs: ADR-0062 (also a ModSecurity v2 parity change to body processing)

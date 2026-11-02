# ADR-0065: The JSON body processor counts arguments like ModSecurity v2

- **Status:** accepted
- **Date:** 2026-11-02
- **Version:** unreleased (post-v3.8.1-cl10)
- **PR:** [#35](https://github.com/cloudlinux/coraza/pull/35)
- **Issue(s):** No linked issue; fork tracking ticket DEF-57965
- **Deciders:** Gabriel Grigoras (CloudLinux)
- **Category:** Parity (ModSecurity v2 JSON body processor)

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

## Decision Drivers

- The same body should give the same `ARGS`, and the same `REQBODY_ERROR`, under
  both engines, so one ruleset behaves the same on either.
- Rules should not run over entries ModSecurity never produces.
- No work for a body past the point where its arguments stop being stored.

## Considered Options

- Keep Coraza's behaviour.
- Count length entries against the limit but keep them.
- Align the JSON processor with ModSecurity: share the limit with `ARGS_GET` and
  `ARGS_PATH`, drop the length entries, trip only when a value would be added and
  stop the walk there.
- The same, for every body processor at once.

## Decision Outcome

Chosen: **align the JSON processor with ModSecurity**, because it is the only
option under which both engines store the same arguments and raise the same
error. Keeping length entries, counted or not, still shows rules values
ModSecurity does not have.

The transaction passes the number of arguments it already holds in a new
experimental field, `plugintypes.BodyProcessorOptions.ArgumentsUsed`; the JSON
processor starts its count there. Other processors ignore it and still cap their
own collections: the difference was measured for JSON only, and the other
processors are left to a change of their own.

## Technical Discussion

No substantive technical discussion recorded on the PR thread at the time of
writing.

## Participants

- Gabriel Grigoras (CloudLinux): author

## Consequences

- **Positive:** `ARGS` counts and `REQBODY_ERROR` for JSON match ModSecurity 2.9.7
  on every case compared. Bodies with many arrays carry up to half the arguments:
  the 999-array body went from about 142 ms to 61 ms of CPU through a
  production-size ruleset. The length entries that grew with nesting depth
  (GHSA-6r3q-mjv7-xr8m) no longer exist.
- **Negative / follow-up:** a rule that read an array's length from `ARGS`
  (`ARGS:json.items` holding `3`) no longer matches, and `&ARGS` is lower for bodies
  with arrays. A JSON body can now trip the limit because of query arguments, as
  in ModSecurity. Urlencoded, multipart and XML bodies still cap per collection.
  This deviates from upstream Coraza, so later syncs touching
  `internal/bodyprocessors/json.go` need care.

## References

- PR: https://github.com/cloudlinux/coraza/pull/35
- Related ADRs: ADR-0062 (also a ModSecurity v2 parity change to body processing)

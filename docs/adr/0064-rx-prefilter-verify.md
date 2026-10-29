# ADR-0064: `SecRxPreFilterVerify`, a sampled re-check of `@rx` pre-filter skips

- **Status:** accepted
- **Date:** 2026-10-29
- **Version:** unreleased (post-v3.8.1-cl8-2)
- **PR:** [#31](https://github.com/cloudlinux/coraza/pull/31)
- **Issue(s):** No linked issue
- **Deciders:** Gabriel Grigoras (CloudLinux)
- **Category:** Feature

## Context and Problem

`SecRxPreFilter On` (ADR-0049, ADR-0050) makes `@rx` skip its regular expression
when a literal the pattern needs is missing from the input. When the extraction of
those literals is wrong, the rule does not match an input it should match, and
nothing reports it: a silent false negative. One such bug existed and was fixed
(the `&#0*60;` phantom needle).

`scripts/rx-prefilter-gate.sh` (pull request #30) proves, for one ruleset and one
build, that `On` and `Off` agree on every `@rx` pattern, on the CRS corpus and on
logged requests. It runs before a release. It cannot see the inputs production
traffic actually carries, and the ruleset changes more often than Coraza does. A
product that wants to rely on the prefilter also wants a check that keeps running
on the live traffic of every ruleset and every build, and that repairs itself when
it finds a miss.

## Decision Drivers

- A way to run with detection identical to `Off` while learning whether the
  prefilter is wrong on real traffic, before anyone relies on it.
- A cheap setting for when it is trusted: most of the CPU saving kept, the check
  never switched off for good.
- A miss is reported with the rule ID and nothing from the request (no payloads,
  no headers, no credentials).
- After a miss the rule stops relying on the prefilter by itself, and the next
  ruleset load starts clean.
- No change for existing users of `SecRxPreFilter On`.
- Not more public surface than needed.

## Considered Options

- The lab and CI gate only. Already exists; it is a release check, and says nothing
  about inputs it was not given.
- Replay audit logs. Needs request bodies persisted in a plain-text log, which
  puts the passwords of blocked login requests at rest.
- Check every skip, always. Detection is then identical to `Off`, and so is the
  cost: the saving is gone.
- Check a sample of the skips, report a miss, and stop using the prefilter for
  that rule until the rules are loaded again.
- On the first miss, switch the prefilter off for the whole WAF. One wrong rule
  would cost the saving of all the others.
- Switch it off per pattern in the shared compile cache (ADR-0006, ADR-0042). The
  cache is shared by WAF instances, so the switch would survive a reload, which has
  to start clean.

## Decision Outcome

Chosen: **a sampled check, a once-per-rule report and a per-rule self-disable.**

- Directive `SecRxPreFilterVerify <percentage>`, from 0 to 100, decimals allowed
  (`0.5`), default `0`. Like `SecRxPreFilter` it applies to the rules defined after
  it, and does nothing while `SecRxPreFilter` is `Off`. It sets
  `OperatorOptions.RxPreFilterVerify` (a probability from 0 to 1).
- When `@rx` decides not to run its regex (the input is shorter than the minimum
  match length, a required literal is missing, or the `^literal$` shortcut says
  "not equal"), it runs the regex anyway with that probability. `100` checks every
  decision, so the rules match exactly as with `Off` and only the prefilter's own
  time is added. `0` never checks.
- When the regex matches, the prefilter was wrong. The operator uses the regex's
  answer, so the request that found the miss is still evaluated correctly. It then
  stops using the prefilter, the minimum length and the shortcut for that rule
  (an atomic flag on the operator, which a ruleset reload replaces) and calls
  `OperatorOptions.RxPreFilterMiss` once.
- The engine turns `RxPreFilterMiss` into a call of the observer configured with
  `experimental.WAFConfigWithRxPreFilterObserver(cfg, func(ruleID int))`, the same
  capability-interface pattern as `WAFConfigWithRuleObserver`. The argument is the
  rule ID, the chain starter's for a chained rule, and nothing else. The rule ID
  is read when the miss happens, because the `id` action is parsed after the
  operator.
- A sampled decision uses `math/rand/v2`'s package functions, which are safe for
  concurrent use and take no lock. The flag is read with one atomic load per
  evaluation.

## Technical Discussion

No substantive technical discussion recorded on the PR thread. The design follows
an internal CloudLinux review comment on the gate, which cannot be quoted here: a
check at probability `p`, reported by rule ID, with the prefilter switched off for
that rule until the next ruleset load.

## Participants

- Gabriel Grigoras (CloudLinux): author

## Consequences

- **Positive:** A fleet can run with the prefilter in the loop at `100` and learn,
  per rule, whether it ever rejects a match, with detection unchanged. A trusted
  setting of `1` keeps about 99% of the saving and still checks every ruleset and
  build. A wrong rule repairs itself and tells you which one it is.
- **Negative / follow-up:** At a probability below `100` a miss is found only by a
  checked decision, so the inputs that reach a wrong rule before it is caught pass
  that rule unchecked: about `1/p` of them per rule and WAF between ruleset loads.
  The lab gate stays the first line; this is the residual check. The switch is per
  rule, not per pattern: two rules with the same regex each find their own miss.
  A decision of the `^literal$` shortcut that says "equal" is not checked, only
  "not equal" is, because the miss being looked for is a lost match. The directive
  adds a few fields to `plugintypes.OperatorOptions`, which is experimental API.
  Cost at `100` is measured by whoever turns it on; it is not a claim of this ADR.

## References

- Related ADRs: ADR-0006 (regex memoize cache), ADR-0042 and ADR-0043 (memoizer
  lifecycle), ADR-0049 (`@rx` literal prefilter), ADR-0050 (`SecRxPreFilter`)

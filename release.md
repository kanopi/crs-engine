# kanopi/crs-engine 1.0.0

First stable release. Ships CRS **v4.28.0** — 622 parsed entries: 587 top-level
rules, 67 chain conditions, 6 `SecAction` directives, 29 `SecMarker`
placeholders, with 6 recorded parser warnings.

**703 tests**, 3715 assertions, green on PHP 8.1 through 8.5. PHPCS, PHPStan at
level `max`, Rector, and a per-directory coverage floor all enforced in CI.

---

## Read this first if you are on 0.1.0

**1.0.0 is the first release where the engine actually enforces.** In 0.1.0 the
detection pipeline was substantially inert, and not in ways that were visible
from the outside:

- **Anomaly-score blocking never fired.** Rules 949110 and 959100 were dead, so
  `anomalyThresholds` had no effect at all. Requests that scored well past the
  threshold were returned as `allow`.
- **`TX:` targets never resolved**, so 242 of 583 rules could not fire.
- **`skipAfter` never terminated**, silently discarding the remainder of the
  ruleset from the first skip onwards.
- **Chain parsing swallowed rules** — 51 lost outright, 29 chained rules left
  firing on their broad condition alone.
- **Response-phase scores were computed and then discarded.**

So the practical effect of upgrading is that **traffic which previously passed
will now be blocked**, because previously almost nothing was. Do not treat this
as a drop-in upgrade.

**Roll it out in monitor mode first.** Run `mode: MODE_MONITOR` over real
traffic, group `CrsVerdict::$matchedRules` by rule id, and build your exclusion
list from what you actually see before you let it block. The
[Tuning for a CMS](README.md#tuning-for-a-cms) section covers this, including a
starting exclusion set and the rules most likely to trip on editorial content.

---

## Breaking changes

### `anomalyThresholds` is keyed by direction, not by severity

```php
// 0.1.0 — read as one threshold per severity, which it never was
anomalyThresholds: ['critical' => 5, 'error' => 4, 'warning' => 3, 'notice' => 2]

// 1.0.0
anomalyThresholds: ['inbound' => 5, 'outbound' => 4]
```

There were only ever two thresholds and they were directional. The old
spellings still work as deprecated aliases — `critical` maps to `inbound`,
`error` to `outbound` — and emit `E_USER_DEPRECATED`. `warning` and `notice`
never mapped to anything; they are accepted, ignored, and warned about.

If you were tuning per-severity, what you actually wanted is the new
`severityScores`, which sets what each severity *adds* to the score. The
thresholds are what the running total is compared against. These are the two
halves of the anomaly model and were easy to confuse, which is why the rename
happened.

### Outbound no longer blocks by default

`responseMode` defaults to `monitor`, independent of `mode`. Response rules are
still evaluated and still populate `matchedRules` and `totalScore` — they just
do not return `block` unless you ask.

The reason: the outbound threshold is 4, and 59 of the 61 response rules that
carry a message are severity `error` or `critical`, worth 4 and 5. A single
match is already over the line, so there is no anomaly accumulation outbound the
way there is inbound. In a sweep of seven ordinary pages a CMS renders, three
were blocked — a documentation page listing `fopen` and `fwrite` trips 953110, a
tutorial showing a Java stack trace trips 952110. Blocking a response is also
heavier than rejecting a request: the application has already done the work, and
the visitor gets an error instead of a page that was fine.

Opt in with `responseMode: CrsConfig::MODE_BLOCK` when your logs say it is safe.

### `TransformRegistry::recordUnknown()` and `unknownTransforms()` are gone

Unknown transforms are now reported at parse time into `rules/manifest.json`,
which is where the docblock always claimed they went. The runtime methods wrote
into a property no production code read, on an object rebuilt for every
`evaluate()` call.

---

## Behaviour changes worth knowing about

None of these change a signature, and all of them change what a verdict says.

- **`ARGS` now carries everything it should.** It is the concatenation of the
  query and body bags, so two parameters sharing a name are two values and both
  get inspected. Previously a name-keyed union dropped the POST value on
  collision, which meant one benign query parameter suppressed every `ARGS`
  rule — most of the ruleset.
- **Request and response bodies are parsed into `ARGS`.** urlencoded and JSON
  are decoded when nothing else supplied `postArgs`; XML was already parsed.
  Across seven attack payloads in a JSON body, detection went from 1 of 7 to 7
  of 7.
- **Inspection is capped.** `maxArgs` 255, `maxArgBytes` 131072,
  `maxRequestBodyBytes` 131072, `maxResponseBodyBytes` 524288 — all
  configurable, `CrsConfig::UNLIMITED` to disable. Requests beyond the caps are
  inspected less than they would have been, and say so on
  `CrsVerdict::$truncations`. Argument *counting* is never capped, so the CRS
  rules that flag an over-large request still fire.
- **`@within` compares complete entries**, not substrings. Previously the
  method `OST` passed method enforcement because it occurs inside `POST`, and an
  empty value matched every allow-list.
- **`ctl:ruleRemoveById` and `ctl:ruleRemoveByTag` are honoured.** Without them,
  920540 flagged `\uXXXX` — ordinary JSON string escaping — so every JSON
  request carrying an accented character or emoji was rejected.
- **Six anti-evasion transforms now run**: `jsDecode`, `cssDecode`,
  `escapeSeqDecode`, `normalizePath`, `normalizePathWin`, `removeCommentsChar`.
  76 occurrences across 52 rules were previously skipped, so those rules matched
  against less-normalised input than upstream intends.

---

## New in this release

**Diagnostics on the verdict.** `CrsVerdict` gained `$operatorErrors` and
`$truncations`, and `toArray()` reports both. Between them they answer "did the
engine actually inspect this request", which previously had no answer:

| report | meaning |
|---|---|
| `operatorErrors` | a rule could not be evaluated — a regex abandoned on a PCRE resource limit. Not the same as finding nothing. |
| `body_too_large_to_parse` | the body exceeded the inspection cap |
| `json_body_unparsable` | the body claimed to be JSON and was not |
| `multipart_body_unparsed` | a multipart body arrived and nothing populated `postArgs` |
| `args`, `arg_bytes`, `request_body`, `response_body`, `xml_body` | an inspection cap engaged |

**Directional configuration.** `requestMode` / `responseMode` override `mode`
per direction; body limits are separate per direction. `anomalyThresholds` was
already directional.

**`failClosedOnOperatorError`** — off by default. When on, a request the engine
could not fully inspect is treated as blocked.

**A PL1 SQL tautology rule** in `supplemental/`, covering the `' OR 1=1` family
that upstream catches with libinjection at PL1 and this engine cannot. Measured
at 10/10 tautology variants detected and 0/32 false positives across realistic
CMS prose.

**`bin/crs-explain` follows the rule's phase.** Testing a payload against a
`RESPONSE-*` rule used to print "did not match payload" for a rule it had never
run, because it built a request and called `evaluate()`.

**Refresh integrity.** `bin/refresh-crs` verifies a content digest of the rule
files against `.crs-version` and leaves `rules/` untouched on a mismatch. The
swap is atomic — `rules/` is never absent, even briefly.

---

## Performance

```
cold start (rule load + first evaluation)   24 ms
steady-state                                3.6 ms per request
```

Across 622 rules, on a four-argument POST. The ruleset is memoised per process,
so the cold start is paid once per PHP-FPM worker.

---

## Known limitations

Deliberate, documented, and unchanged by this release.

**libinjection is not ported.** CRS 941100 and 942100 — the libinjection-backed
XSS and SQLi detectors — cannot run, so they are skipped with a warning. The
other 50+ SQLi and 40+ XSS rules are pure `@rx` and work normally, and
`supplemental/` covers the most-exploited PL1 gap. Two payload families still
need PL2: `admin'--` and backtick RCE.

**Multipart bodies are yours to supply.** Boundaries, part headers, transfer
encodings and file parts are a real parser, and it is the format where
disagreeing subtly with your application creates bypasses rather than closing
them. Pass `postArgs`, plus `files` / `multipartFlags` / `multipartPartHeaders`
if your parser can produce them. A multipart body with no `postArgs` reports
`multipart_body_unparsed`.

**Two `ctl:` forms are reported but not honoured** —
`ctl:ruleRemoveTargetByTag` and `ctl:forceRequestBodyVariable`, one occurrence
each in the shipped ruleset. Both appear in `manifest.json` so they cannot drift
silently.

**CRS at PL1 flags some editorial content.** Four of twenty realistic benign
requests are blocked at default config: a post body containing
`cat /etc/hosts | grep`, a regex in a support ticket, a JSON blob pasted into a
form field, and a path containing `../`. This is upstream behaviour on
user-generated content, not an engine defect, and it needs exclusions — see
[Tuning for a CMS](README.md#tuning-for-a-cms).

**The content digest is not a signature.** It detects ruleset substitution
between two fetches; it does not authenticate the publisher. `--bump` re-pins by
definition, so the weekly refresh is trust-on-first-use and the `rules/` diff is
the real review gate.

---

## Upgrading

1. Rename `anomalyThresholds` keys to `inbound` / `outbound`, or leave them and
   watch for the deprecation notice.
2. Move any per-severity tuning to `severityScores`.
3. Run `mode: MODE_MONITOR` over real traffic and build an exclusion list from
   `matchedRules` before enabling blocking.
4. Decide whether you want outbound blocking. It is off now.
5. If you build `RequestData` by hand, pass `postArgs` — your framework's decode
   is the one the application will act on, and using it avoids a parser
   differential. Send an accurate `Content-Type` either way.
6. Log `CrsVerdict::$truncations` and `$operatorErrors`. A clean verdict
   alongside a non-empty list means less was inspected than it appears.

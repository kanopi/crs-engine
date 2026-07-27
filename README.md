# kanopi/crs-engine

A standalone, pure-PHP engine that parses the
[OWASP Core Rule Set](https://coreruleset.org/) and evaluates HTTP requests
against it. No FFI, no sidecars, no external runtimes — just PHP.

It exists so that a PHP-based firewall (or any PHP application) can speak the
same rule format as ModSecurity / Coraza / CRS without shelling out, embedding
a Go binary, or hand-translating thousands of regexes.

This package is a sibling of `kanopi/firewall` and is consumed by it through
a thin plugin adapter — but the engine itself depends on nothing in the
firewall and can be used standalone in any framework (Symfony, Laravel,
Drupal, WordPress, raw PHP).

---

## Table of contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [The request DTO](#the-request-dto)
- [The verdict](#the-verdict)
- [Supported SecLang subset](#supported-seclang-subset)
- [Detection coverage](#detection-coverage)
- [Rule scope](#rule-scope)
- [Refreshing CRS rules](#refreshing-crs-rules)
- [Debugging a rule](#debugging-a-rule)
- [Testing](#testing)
- [Code quality checks](#code-quality-checks)
- [CircleCI pipeline](#circleci-pipeline)
- [Project layout](#project-layout)
- [Versioning](#versioning)
- [License and attribution](#license-and-attribution)

---

## How it works

The engine has three stages:

1. **Refresh (build time)** — `bin/refresh-crs` downloads a pinned CRS release
   from GitHub, parses every `REQUEST-*.conf` file with the bundled SecLang
   parser, and writes the result to `rules/`:
   - `rules/<source>.json` — one human-reviewable JSON file per CRS source
     file, used to make diff review of CRS bumps painless.
   - `rules/compiled.php` — a single `var_export`'d PHP array that opcache
     can preload, used as the runtime hot path.
   - `rules/manifest.json` — version, rule counts, parser warnings.

2. **Load (process start)** — `CrsEngine`'s constructor reads
   `rules/compiled.php` once. With opcache enabled, subsequent processes hit a
   warm cache and pay almost no cost.

3. **Evaluate (per request)** — the application adapts its framework request
   into a `RequestData` DTO and calls `$engine->evaluate($request)`. The
   evaluator resolves CRS target expressions against the request, applies
   transforms, runs operators (mostly `@rx`), accumulates per-category
   anomaly scores, and returns a `CrsVerdict` carrying the action
   (`allow` / `log` / `block`), matched rules, and scores.

The refresh step runs on a schedule in CI — never on production hot paths.

---

## Requirements

- PHP 8.1 or higher (no upper bound; tested in CI against 8.1, 8.2, 8.3)
- `ext-json`, `ext-mbstring`, `ext-pcre` (all bundled with standard PHP builds)
- Composer

The package has **no runtime composer dependencies** — only `phpunit`,
`phpstan`, `rector`, and `php_codesniffer` for development.

---

## Installation

```sh
composer require kanopi/crs-engine
```

After installing, generate the rule cache once:

```sh
vendor/bin/refresh-crs
```

This downloads the CRS release pinned in the package's `.crs-version` and
populates `vendor/kanopi/crs-engine/rules/`. You only need to do this on
fresh installs or when the pinned tag changes.

---

## Quick start

```php
use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\Request\RequestData;

$engine = new CrsEngine(new CrsConfig(
    paranoia: 1,
    mode: CrsConfig::MODE_BLOCK,
));

$request = new RequestData(
    method:      'GET',
    uri:         '/login?user=admin&pw=' . rawurlencode("' OR 1=1"),
    rawUri:      $_SERVER['REQUEST_URI'] ?? '/',
    queryString: $_SERVER['QUERY_STRING'] ?? '',
    protocol:    'HTTP/1.1',
    remoteAddr:  $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
    queryArgs:   $_GET,
    postArgs:    $_POST,
    cookies:     $_COOKIE,
    headers:     getallheaders() ?: [],
);

$verdict = $engine->evaluate($request);

if ($verdict->isBlocked()) {
    http_response_code(403);
    error_log(sprintf(
        'CRS blocked request: rule %d (%s)',
        $verdict->blockingRuleId,
        $verdict->matchedRules[0]['msg'] ?? '',
    ));
    exit;
}
```

For framework-specific adapters (Symfony `Request`, PSR-7, Laravel
`Illuminate\Http\Request`, Drupal `Symfony\HttpFoundation\Request`), write a
small mapper that produces `RequestData`. There is intentionally no built-in
adapter — keeping the engine framework-free is the point.

---

## Configuration

All configuration is constructor arguments on `CrsConfig`. Build it directly
or with `CrsConfig::fromArray()` if you load config from YAML / env.

```php
new CrsConfig(
    paranoia: 1,                        // 1 (default) - 4. Higher = more strict, more false positives.
    mode: CrsConfig::MODE_BLOCK,        // or MODE_MONITOR (records matches, never blocks)
    anomalyThresholds: [
        'inbound'  => 5,                // request score >= this blocks the request
        'outbound' => 4,                // response score >= this blocks the response
    ],
    disabledRules:      [920300, 942130],     // skip these rule IDs
    disabledCategories: ['session_fixation'], // skip whole categories
    rulesPath:          null,                 // override location of compiled.php
    severityScores: [
        'critical' => 5,                // what each severity *adds* to the score
        'error'    => 4,
        'warning'  => 3,
        'notice'   => 2,
    ],
);
```

| Field | Default | Notes |
|---|---|---|
| `paranoia` | `1` | Rules tagged with `paranoia-level/N` above this are skipped. |
| `mode` | `block` | `monitor` evaluates and records matches but never returns `block`. |
| `anomalyThresholds` | `['inbound' => 5, 'outbound' => 4]` | Score at which to block, per direction. There are exactly two thresholds. |
| `disabledRules` | `[]` | List of CRS rule IDs to skip — useful for known false positives. |
| `disabledCategories` | `[]` | Skip an entire category (`sqli`, `xss`, `lfi`, etc.) for targeted tuning. |
| `rulesPath` | bundled `rules/` | Point at a custom rule directory (used for testing and custom rulesets). |
| `severityScores` | CRS defaults | Anomaly contribution per severity. Upstream exposes these in `crs-setup.conf`. |

### Thresholds vs. severity scores

These are the two halves of the anomaly model and are easy to confuse:

- **`severityScores`** is what a matching rule *adds*. A `severity:CRITICAL`
  rule contributes 5 by default.
- **`anomalyThresholds`** is what the running total is *compared against*.
  Cross the inbound threshold and CRS rule 949110 blocks the request; cross
  the outbound one and 959100 blocks the response.

So the defaults mean "block a request once it accumulates one critical-severity
detection". Raise `inbound` to 10 to require two.

> **Deprecated:** `anomalyThresholds` previously took severity keys, where
> `critical` silently meant *inbound* and `error` meant *outbound*, while
> `warning` and `notice` did nothing at all. Those spellings still work and
> emit `E_USER_DEPRECATED`; `warning`/`notice` are ignored. Unrecognised keys
> now throw `ConfigurationException` instead of being silently accepted.

---

## The request DTO

`Kanopi\Crs\Request\RequestData` is the framework-agnostic input. Build it
once per request from whatever your framework provides:

```php
new RequestData(
    method:      'POST',
    uri:         '/api/comments',
    rawUri:      '/api/comments',
    queryString: '',
    protocol:    'HTTP/1.1',
    remoteAddr:  '203.0.113.42',
    queryArgs:   $request->query->all(),         // GET params
    postArgs:    $request->request->all(),       // POST/form params
    cookies:     $request->cookies->all(),
    headers:     $request->headers->all(),       // name => string|string[]
    body:        (string) $request->getContent(),
    files:       [],                              // [{name, filename, mime, size}]
);
```

`RequestData::fromGlobals()` is provided for CLI experimentation but should
not be used in framework integrations — your framework has a richer,
already-parsed request object.

---

## The verdict

`CrsEngine::evaluate()` returns a `Kanopi\Crs\CrsVerdict`:

```php
$verdict->action;          // 'allow' | 'log' | 'block'
$verdict->isBlocked();     // bool
$verdict->blockingRuleId;  // ?int — the first rule that fired with deny/block/drop
$verdict->totalScore;      // accumulated anomaly score across paranoia levels
$verdict->scores;          // per-category: ['sqli' => 5, 'xss' => 0, ...]
$verdict->matchedRules;    // array of [id, msg, severity, score, tags, category, matched_data]
$verdict->toArray();       // serialisable shape for logging
```

In `monitor` mode `action` is `log` whenever any rule matched and `allow`
otherwise — `isBlocked()` always returns false. In `block` mode, the first
rule that asks to deny short-circuits evaluation.

---

## Supported SecLang subset

The parser is deliberately narrower than full ModSecurity. It covers
everything CRS 4.x uses in its `REQUEST-*` rule files, with the explicit
exception of operators that need libinjection.

**Directives:** `SecRule` (full), `SecAction`/`SecMarker` (parsed and
ignored — used only as skipAfter targets).

**Operators (16):** `@rx`, `@pm`, `@pmf`, `@beginsWith`, `@endsWith`,
`@contains`, `@containsWord`, `@streq`, `@eq`/`@gt`/`@lt`/`@ge`/`@le`,
`@within`, `@ipMatch` (with CIDR), `@validateByteRange`,
`@validateUrlEncoding`, `@validateUtf8Encoding`.

Unsupported operators (`@detectSQLi`, `@detectXSS`, etc.) cause the rule
to be parsed-and-skipped with a warning recorded in `manifest.json`.
These two operators back CRS rules **942100** and **941100** specifically —
the *libinjection-backed* SQLi and XSS detectors. The other 50+ SQLi and 40+
XSS rules in CRS are pure `@rx` and work normally. See
[Detection coverage](#detection-coverage) for what that costs in practice
and what the engine does about it.

**Transforms (20+):** `none`, `lowercase`/`uppercase`,
`urlDecode`/`urlDecodeUni`, `htmlEntityDecode`,
`compressWhitespace`/`removeWhitespace`, `replaceNulls`/`removeNulls`,
`utf8toUnicode`, `base64Decode`/`base64DecodeExt`, `cmdLine`,
`normalisePath`, `length`, `sha1`/`md5`, `trim`,
`removeComments`/`replaceComments`.

**Variables (targets):** `ARGS`, `ARGS_GET`, `ARGS_POST`, `ARGS_NAMES`,
`ARGS_GET_NAMES`, `ARGS_POST_NAMES`, `REQUEST_URI`, `REQUEST_URI_RAW`,
`REQUEST_FILENAME`, `REQUEST_METHOD`, `REQUEST_PROTOCOL`, `REQUEST_LINE`,
`REQUEST_BODY`, `REQUEST_HEADERS`, `REQUEST_HEADERS_NAMES`,
`REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `QUERY_STRING`, `REMOTE_ADDR`,
`FILES_NAMES`, `TX:<name>`.

Target modifiers `!collection:selector` (exclude), `&collection`
(count), and regex selectors `collection:/pattern/` are all supported.

**Actions:** `id`, `phase`, `block`/`deny`/`drop`/`pass`/`allow`, `chain`,
`capture`, `multiMatch`, `t:*`, `msg`, `logdata`, `severity`, `tag`,
`ver`/`rev`/`maturity`/`accuracy` (recorded but unused at runtime),
`setvar`, `skipAfter`. `ctl:*`, `expirevar`, `deprecatevar`, and similar
state-management actions are accepted by the parser and silently ignored.

---

## Detection coverage

The engine cannot run CRS 942100 and 941100, the two libinjection-backed
detectors, and those are the PL1 backbone for SQL injection. Measured against
34 attack payloads and 32 samples of realistic CMS/search traffic:

| Paranoia | Attacks blocked | False positives |
|---|---|---|
| **1** (default) | 30/34 (88%) | **0/32 (0%)** |
| 2 | 32/34 (94%) | 4/32 (12.5%) |
| 3 | 32/34 (94%) | 10/32 (31%) |
| 4 | 34/34 (100%) | 27/32 (84%) |

**Raising the default to PL2 is not recommended.** The rules that come in at
PL2 block ordinary content — markdown post bodies, JSON API payloads, code
snippets in comment fields, quoted prose. PL3 additionally blocks accented,
CJK and Arabic names. Both are usable, but only with a per-site exclusion
list built from real traffic; see `disabledRules` and `disabledCategories`.

### What the engine adds

`supplemental/REQUEST-948-TAUTOLOGY.conf` ships one engine-owned rule,
**948100**, covering the `' OR '1'='1` / `OR 1=1` family that libinjection
would otherwise catch at PL1. It is parsed alongside CRS by `bin/refresh-crs`
and survives CRS bumps because it lives outside `rules/`. It is tagged
`kanopi-crs-engine` so it is easy to tell apart from upstream rules, and it
can be turned off like any other rule:

```php
new CrsConfig(disabledRules: [948100]);
```

Its false-positive profile is pinned by `tests/Integration/PayloadCorpusTest.php`,
which fails the build if it starts flagging ordinary prose.

### Known gaps at PL1

These need real tokenisation and are deliberately **not** chased with regex,
because every pattern that catches them also catches ordinary content:

| Payload | Why not | Caught at |
|---|---|---|
| `admin'--` | collides with quoted prose using `--` | PL2 |
| `` `id` `` | collides with inline code in comment fields | PL2 |
| RFI by hostname | needs `TX:` regex selectors (unimplemented) | PL4 |

If you need these at PL1, run PL2 with an exclusion list, or open an issue
about porting libinjection.

---

## Rule scope

Only request-side CRS rule files are parsed (response inspection is out of
scope for v1):

```
REQUEST-911-METHOD-ENFORCEMENT
REQUEST-913-SCANNER-DETECTION
REQUEST-920-PROTOCOL-ENFORCEMENT
REQUEST-921-PROTOCOL-ATTACK
REQUEST-922-MULTIPART-ATTACK
REQUEST-930-APPLICATION-ATTACK-LFI
REQUEST-931-APPLICATION-ATTACK-RFI
REQUEST-932-APPLICATION-ATTACK-RCE
REQUEST-933-APPLICATION-ATTACK-PHP
REQUEST-934-APPLICATION-ATTACK-GENERIC
REQUEST-941-APPLICATION-ATTACK-XSS
REQUEST-942-APPLICATION-ATTACK-SQLI
REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION
REQUEST-944-APPLICATION-ATTACK-JAVA
REQUEST-949-BLOCKING-EVALUATION
```

`RESPONSE-*` files and CRS's own config/init files
(`REQUEST-901-INITIALIZATION`, `REQUEST-905-COMMON-EXCEPTIONS`,
`RESPONSE-980-CORRELATION`) are not parsed.

---

## Refreshing CRS rules

`bin/refresh-crs` is the single entry point for keeping the rule cache
current. It is **deliberately not run at runtime** — only at build / CI time.

```sh
# Use the tag pinned in .crs-version
bin/refresh-crs

# Look up the latest stable CRS release on GitHub, update the pin, parse
bin/refresh-crs --bump

# Pin to a specific tag
bin/refresh-crs --tag=v4.7.0

# Parse but don't overwrite rules/
bin/refresh-crs --dry-run
```

What it does:

1. Reads `.crs-version` (or applies the override flag).
2. Downloads `https://github.com/coreruleset/coreruleset/archive/refs/tags/<tag>.tar.gz`.
3. Extracts to a temp directory with `PharData`.
4. Parses every supported `REQUEST-*.conf` with the bundled `SecLangParser`.
5. Writes `rules/<source>.json`, `rules/manifest.json`, and
   `rules/compiled.php`.
6. Updates `.crs-version` with the new tag.

The result is normal, reviewable git changes. The intended pattern for
production projects is a scheduled CI job that runs `--bump` weekly, opens a
PR with the regenerated rules, and lets a maintainer review the diff before
merging. CircleCI's `weekly-refresh` workflow in this repo demonstrates that
pattern.

### Version pin format

`.crs-version` is a plain key=value file:

```
tag=v4.0.0
sha=
source=https://github.com/coreruleset/coreruleset
```

The `source` field can point at a fork or mirror. `sha` is populated for
provenance but not enforced.

---

## Debugging a rule

`bin/crs-explain` prints the parsed form of a CRS rule and optionally tests
a payload against it:

```sh
# Show how rule 942260 is parsed
bin/crs-explain 942260

# Test a payload against it
bin/crs-explain 942260 --payload="' UNION SELECT password FROM users"
```

Output includes the rule's targets, transforms, operator, message, tags, and
whether your payload matches. Useful for diagnosing false positives without
trawling through CRS source.

---

## Testing

Two test suites, separated by speed and scope.

```sh
# Everything (54 tests, fast)
composer test

# Just the unit tests
composer test:unit

# Just the integration tests
composer test:integration

# With coverage
XDEBUG_MODE=coverage vendor/bin/phpunit --coverage-html coverage/
```

**Unit tests** (`tests/Unit/`) cover the parser, transforms, operators, and
the TxStore against hand-crafted SecLang snippets — no network, no real CRS
download.

**Integration tests** (`tests/Integration/`) run real-shaped CRS rules from
bundled fixtures (`tests/Integration/fixtures/REQUEST-*.conf`) against
real attack payloads:

- SQLi: `UNION SELECT`, `' OR 1=1`, `DELETE FROM`, URL-encoded variants,
  monitor-mode behavior, disabled-rule behavior.
- XSS: `<script>` tags, `javascript:` URIs, event handlers, HTML-entity-
  encoded payloads.
- Refresh flow: parse → write → load round-trip.

The fixture files mirror the format and identifier ranges of real CRS rules,
so the integration tests double as regression checks for the parser.

---

## Code quality checks

All three static analysis tools are wired into composer scripts and CI:

```sh
# Individual checks
composer check:code      # PHPCS (PSR-12 + PHPCompatibility for PHP 8.1+)
composer check:stan      # PHPStan at level max
composer check:rector    # Rector --dry-run

# All checks at once
composer check

# Auto-fix what's mechanically fixable
composer fix             # Rector + PHPCBF in order
```

PHPStan runs at `level: max`. The full firewall library's pragmatic
identifier ignores (`argument.type`, `cast.string`, `missingType.iterableValue`)
are inherited so untrusted-JSON ingestion paths stay tractable.

Rector targets `LevelSetList::UP_TO_PHP_81` so the engine stays compatible
with the lower PHP bound while still picking up modern idioms (readonly
properties, constructor promotion, etc.).

---

## CircleCI pipeline

`.circleci/config.yml` mirrors `kanopi/firewall` — it uses the
`kanopi/ci-tools@2` orb, runs every check on a PHP-version matrix
(`8.1`, `8.2`, `8.3`, `8.4`, `8.5`), and exposes three workflows.

| Workflow | Trigger | Jobs (each runs across the full PHP matrix) |
|---|---|---|
| `test` | every push / PR | `phpunit`, `phpstan` (via `check:stan:circleci`), `rector` (`check:rector:circleci`), `quality` (`check:code:circleci`) |
| `weekly-refresh` | scheduled trigger with `pipeline-trigger=weekly-refresh` | `refresh-and-branch` (runs `refresh-crs --bump`, all static checks, all tests, then pushes a `chore/crs-refresh-<tag>-<date>` branch) |
| `release` | tag push matching `vX.Y.Z` | Same matrix as `test`, but gated to tag pushes — green on every PHP version is the prerequisite for the release tag to ship. |

Each matrix job publishes JUnit results and stores the per-tool reports
(`phpcs-report.xml`, `phpstan-report.xml`, `rector-report.xml`,
`reports/junit.xml`) as CircleCI artifacts.

To wire up the weekly bump:

1. In CircleCI's project settings, add a **Scheduled Pipeline**:
   - Schedule: `0 6 * * 1` (Mondays 06:00 UTC)
   - Pipeline parameter: `pipeline-trigger` = `weekly-refresh`
2. Ensure the `kanopi-code` CircleCI context is attached. It carries the
   shared deploy SSH key (consumed by `ci-tools/copy-ssh-key`), the
   GitHub token for `gh pr create`, and the Docker Hub credentials.

The job:
1. Runs `bin/refresh-crs --bump` to fetch the latest upstream CRS release.
2. Re-runs phpcs / phpstan / rector / phpunit against the refreshed ruleset.
3. If anything changed in `.crs-version` or `rules/`, commits to a new
   `chore/crs-refresh-<tag>-<date>` branch.
4. Pushes the branch and **opens a PR automatically** via `gh pr create`,
   labelled `crs-bump`, with rule counts and warning counts in the body.

A maintainer reviews the diff and merges — the only human step.

---

## Project layout

```
crs-engine/
├── bin/
│   ├── refresh-crs           Download + parse + write CRS rules
│   └── crs-explain           Debug a parsed rule against a payload
├── rules/                    Generated by refresh-crs (gitignored or committed per project policy)
│   ├── compiled.php          Runtime hot path (var_export'd)
│   ├── manifest.json         Version, counts, parser warnings
│   └── REQUEST-*.json        Per-source-file JSON for review
├── src/
│   ├── CrsEngine.php         Public entry point
│   ├── CrsConfig.php
│   ├── CrsVerdict.php
│   ├── Exception/
│   ├── Operators/            16 SecLang operators + registry
│   ├── Parser/               SecLang parser + DTOs
│   ├── Refresh/              CrsFetcher, RuleWriter, VersionPin, RefreshRunner
│   ├── Request/RequestData.php   Framework-agnostic request DTO
│   ├── Runtime/              RuleEvaluator, RuleSet, TxStore, TransformPipeline
│   ├── Transforms/           20+ SecLang transforms + registry
│   └── Variables/            VariableResolver (ARGS, REQUEST_HEADERS, etc.)
├── tests/
│   ├── Integration/
│   │   ├── fixtures/         CRS-shaped .conf files used by integration tests
│   │   ├── RefreshFlowTest.php
│   │   ├── SqliRulesTest.php
│   │   └── XssRulesTest.php
│   └── Unit/
│       ├── Operators/
│       ├── Parser/
│       ├── Runtime/
│       └── Transforms/
├── .circleci/config.yml
├── .crs-version              Pinned upstream CRS tag
├── composer.json
├── phpcs_ruleset.xml         PSR-12 + PHPCompatibility 8.1+
├── phpstan.neon              level: max
└── rector.php                UP_TO_PHP_81 + standard set list
```

---

## Versioning

The engine follows semver, with CRS pin bumps driving the change type:

- **Patch** (`v0.1.1` → `v0.1.2`): engine bug fix, no parser/runtime API
  change, no CRS bump.
- **Minor** (`v0.1.x` → `v0.2.0`): CRS bump (any), new operators or
  transforms, parser improvements that are strictly additive.
- **Major** (`v0.x` → `v1.0`): breaking change to `CrsEngine` / `CrsConfig`
  / `CrsVerdict` / `RequestData` public API.

Each release commit carries the CRS tag it ships with in its message, e.g.
`Release v0.3.0 (CRS v4.7.0)`. The shipped `.crs-version` is authoritative.

---

## License and attribution

The engine code is licensed under the [MIT License](LICENSE) (see
`composer.json`).

CRS rule content under `rules/` is a derived work of the
[OWASP Core Rule Set](https://github.com/coreruleset/coreruleset), which is
licensed under Apache 2.0. The CRS `NOTICE` and `LICENSE` files are copied
into `rules/` on every refresh; please retain them when redistributing.

This package does not vendor or republish CRS — it downloads it on demand
during the refresh step.

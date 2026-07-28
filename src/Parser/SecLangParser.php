<?php

declare(strict_types=1);

namespace Kanopi\Crs\Parser;

use Kanopi\Crs\Exception\ParseException;
use Kanopi\Crs\Transforms\TransformRegistry;

/**
 * Parses ModSecurity SecLang .conf files into ParsedRule objects.
 *
 * Scope is the subset CRS 4.x uses across its REQUEST-* and RESPONSE-* rule
 * files, plus this engine's own supplemental/ rules.
 *
 * Directives: SecRule, SecAction (an unconditional rule — CRS relies on it to
 * reset aggregate scores between phases) and SecMarker (a placeholder that
 * holds its position so skipAfter has a landing point).
 *
 * Out of scope. Two different treatments, because they fail differently:
 *
 * Rule dropped, warning recorded in manifest.json — the detection itself
 * cannot be evaluated, so keeping the rule would be worse than losing it:
 *   - @detectSQLi / @detectXSS  (need libinjection; see supplemental/ for
 *                                what the engine does about the PL1 gap)
 *
 * Rule kept, warning recorded in manifest.json — the detection still works,
 * but an action that would have shaped it is ignored, so the rule behaves
 * differently here than under ModSecurity:
 *   - ctl:* (notably ctl:requestBodyProcessor, which changes what is parsed,
 *     and ctl:ruleRemoveTargetById, which changes what rules apply to)
 *   - expirevar, deprecatevar, initcol, setsid, setuid, setrsc — all imply
 *     cross-request state this engine does not model
 *
 * Ignored in silence, because they are inert rather than unimplemented and
 * warning on them would bury the two lists above:
 *   - ver, rev, maturity, accuracy — metadata
 *   - sanitiseArg, sanitiseRequestHeader, nolog, log, auditlog, noauditlog —
 *     audit-log hints, and this engine writes no audit log
 *   - SecAuditLog and friends as directives, which are not SecRule at all
 */
final class SecLangParser
{
    private const SUPPORTED_OPERATORS = [
        'rx', 'pm', 'pmf', 'beginsWith', 'endsWith', 'contains', 'containsWord',
        'streq', 'eq', 'gt', 'lt', 'ge', 'le', 'within', 'ipMatch',
        'validateByteRange', 'validateUrlEncoding', 'validateUtf8Encoding',
    ];

    /** @var array<int, string> */
    public array $warnings = [];

    /**
     * Used only to tell a transform this engine implements from one it does
     * not, so unknown names can be reported at parse time. Injectable so a
     * caller that has registered its own transforms is not told they are
     * missing.
     */
    private readonly TransformRegistry $transformRegistry;

    /** @var array<int, int> */
    public array $skippedRules = [];

    /**
     * Directory containing .data files referenced by @pmFromFile.
     * Auto-populated from the .conf file's directory in parseFile().
     */
    private ?string $dataFileDir = null;

    public function __construct(?TransformRegistry $transformRegistry = null)
    {
        $this->transformRegistry = $transformRegistry ?? new TransformRegistry();
    }

    /**
     * @return array<int, ParsedRule>
     */
    public function parseFile(string $path): array
    {
        if (!is_file($path)) {
            throw new ParseException('File not found: ' . $path);
        }

        $contents = (string) file_get_contents($path);
        $this->dataFileDir = dirname($path);
        return $this->parseString($contents, basename($path));
    }

    /**
     * @return array<int, ParsedRule>
     */
    public function parseString(string $contents, string $sourceFile = '<string>', ?string $dataFileDir = null): array
    {
        if ($dataFileDir !== null) {
            $this->dataFileDir = $dataFileDir;
        }

        $category   = $this->categoryFromFilename($sourceFile);
        $statements = $this->joinContinuationLines($contents);

        /** @var array<int, ParsedRule> $rules */
        $rules = [];
        /** @var array<int, RuleParseState> $pendingChain */
        $pendingChain = [];
        $pendingChainParent = null;

        foreach ($statements as $line => $stmt) {
            $stmt = trim($stmt);
            if ($stmt === '') {
                continue;
            }

            if (str_starts_with($stmt, '#')) {
                continue;
            }

            $directive = $this->readWord($stmt);
            $rest = trim(substr($stmt, strlen($directive)));

            // SecMarker is the landing point for skipAfter. It has to keep its
            // position in the rule list, otherwise a skip started earlier in
            // the file never terminates and the rest of the ruleset is
            // silently discarded.
            if (strcasecmp($directive, 'SecMarker') === 0) {
                $this->dropUnterminatedChain($pendingChainParent, $pendingChain, $sourceFile, $line, 'SecMarker');

                $name = $this->markerName($rest);
                if ($name !== '') {
                    $rules[] = ParsedRule::marker($name, $category);
                }

                continue;
            }

            // SecAction is unconditional. CRS relies on it to reset the
            // aggregate anomaly scores at the start of phase 2 — without that
            // reset the per-paranoia-level buckets are counted twice, once by
            // the phase-1 aggregation and again by the phase-2 one.
            if (strcasecmp($directive, 'SecAction') === 0) {
                $this->dropUnterminatedChain($pendingChainParent, $pendingChain, $sourceFile, $line, 'SecAction');

                $tokens = $this->tokenize($rest);
                $parsedActions = $this->parseActions($tokens[0] ?? '');
                if ($parsedActions->id === 0) {
                    $this->warnings[] = sprintf('%s:%d — SecAction has no id, skipping', $sourceFile, $line);
                    continue;
                }

                $this->warnUnsupportedActions($parsedActions, $sourceFile, $line);

                $rules[] = ParsedRule::unconditional(
                    $parsedActions->id,
                    $parsedActions->phase,
                    $parsedActions->setvars,
                    $parsedActions->tags,
                    $category,
                );

                continue;
            }

            if (strcasecmp($directive, 'SecRule') !== 0) {
                continue;
            }

            // A chain continuation is identified by position, not by content:
            // it is whatever SecRule follows a rule that declared `chain`.
            // Continuations carry no id of their own, so they must not be run
            // through the "needs an id" check that applies to new rules.
            $isContinuation = $pendingChainParent instanceof RuleParseState;

            try {
                $parsed = $this->parseSecRule($rest, $sourceFile, $line, $category, $isContinuation);
            } catch (ParseException $e) {
                $this->warnings[] = sprintf('%s:%d — %s', $sourceFile, $line, $e->getMessage());
                $this->dropUnparsableChain($pendingChainParent, $pendingChain, $sourceFile, $line, $e->getMessage());
                continue;
            }

            if (!$parsed instanceof RuleParseState) {
                // parseSecRule() already recorded why (unsupported operator, or
                // a new rule with no id). If this was a chain continuation the
                // parent loses its qualifying condition, so the whole chained
                // rule has to go — keeping the parent would make it fire on the
                // broader condition alone.
                $this->dropUnparsableChain($pendingChainParent, $pendingChain, $sourceFile, $line, 'continuation could not be parsed');
                continue;
            }

            if ($isContinuation) {
                $pendingChain[] = $parsed;
                if (!$parsed->hasChainFollow) {
                    /** @var RuleParseState $pendingChainParent */
                    $rules[] = $this->attachChain($pendingChainParent, $pendingChain);
                    $pendingChainParent = null;
                    $pendingChain = [];
                }

                continue;
            }

            if ($parsed->hasChainFollow) {
                $pendingChainParent = $parsed;
                continue;
            }

            $rules[] = $parsed->rule;
        }

        $this->dropUnterminatedChain($pendingChainParent, $pendingChain, $sourceFile, 0, 'end of file');
        $this->warnUnknownTransforms($rules, $sourceFile);

        return $rules;
    }

    /**
     * Report transforms the rules ask for that this engine does not implement.
     *
     * TransformPipeline skips an unknown transform at runtime and carries on,
     * which is the right call mid-request but means the rule quietly runs on
     * less-normalised input than its author assumed — exactly the difference
     * anti-evasion transforms exist to remove. Nothing surfaced that: the
     * registry recorded unknown names into a property no production code ever
     * read, on an object CrsEngine rebuilds for every evaluate() call.
     *
     * Summarised per name rather than per occurrence. CRS v4.26.0 asks for six
     * transforms this engine lacks across 76 occurrences, and 76 lines would
     * bury the six facts worth knowing.
     *
     * @param array<int, ParsedRule> $rules
     */
    private function warnUnknownTransforms(array $rules, string $sourceFile): void
    {
        $counts = [];
        $this->countUnknownTransforms($rules, $counts);

        ksort($counts);
        foreach ($counts as $name => $occurrences) {
            $this->warnings[] = sprintf(
                '%s — transform `t:%s` is not implemented; skipped on %d rule%s, which will '
                . 'therefore match against less-normalised input than upstream intends',
                $sourceFile,
                $name,
                $occurrences,
                $occurrences === 1 ? '' : 's',
            );
        }
    }

    /**
     * @param array<int, ParsedRule> $rules
     * @param array<string, int> $counts
     */
    private function countUnknownTransforms(array $rules, array &$counts): void
    {
        foreach ($rules as $rule) {
            foreach ($rule->transforms as $transform) {
                // `none` is a pipeline directive rather than a transform.
                if (strcasecmp($transform, 'none') === 0) {
                    continue;
                }

                if ($this->transformRegistry->has($transform)) {
                    continue;
                }

                $counts[$transform] = ($counts[$transform] ?? 0) + 1;
            }

            $this->countUnknownTransforms($rule->chain, $counts);
        }
    }

    /**
     * A chain starter whose continuation never arrived is malformed. Drop it
     * rather than emit a parent that would fire without its qualifier.
     *
     * @param array<int, RuleParseState> $pendingChain
     * @param-out null $ruleParseState
     * @param-out array<int, RuleParseState> $pendingChain
     */
    private function dropUnterminatedChain(?RuleParseState &$ruleParseState, array &$pendingChain, string $sourceFile, int $line, string $context): void
    {
        if (!$ruleParseState instanceof RuleParseState) {
            return;
        }

        $this->skippedRules[] = $ruleParseState->rule->id;
        $this->warnings[] = sprintf(
            '%s:%d — rule %d declares chain but no continuation followed (hit %s); dropping the rule',
            $sourceFile,
            $line,
            $ruleParseState->rule->id,
            $context,
        );

        $ruleParseState = null;
        $pendingChain = [];
    }

    /**
     * A continuation that failed to parse takes its parent with it, for the
     * same reason: the parent alone is a weaker condition than the author
     * wrote, which turns a targeted rule into a false-positive generator.
     *
     * @param array<int, RuleParseState> $pendingChain
     * @param-out null $ruleParseState
     * @param-out array<int, RuleParseState> $pendingChain
     */
    private function dropUnparsableChain(?RuleParseState &$ruleParseState, array &$pendingChain, string $sourceFile, int $line, string $reason): void
    {
        if (!$ruleParseState instanceof RuleParseState) {
            return;
        }

        $this->skippedRules[] = $ruleParseState->rule->id;
        $this->warnings[] = sprintf(
            '%s:%d — dropping chained rule %d: %s',
            $sourceFile,
            $line,
            $ruleParseState->rule->id,
            $reason,
        );

        $ruleParseState = null;
        $pendingChain = [];
    }

    /**
     * @param array<int, RuleParseState> $chain
     */
    private function attachChain(RuleParseState $ruleParseState, array $chain): ParsedRule
    {
        $children = [];
        foreach ($chain as $c) {
            $children[] = $c->rule;
        }

        $r = $ruleParseState->rule;
        return new ParsedRule(
            id:               $r->id,
            phase:            $r->phase,
            operator:         $r->operator,
            operatorArgument: $r->operatorArgument,
            operatorNegated:  $r->operatorNegated,
            targets:          $r->targets,
            transforms:       $r->transforms,
            action:           $r->action,
            severity:         $r->severity,
            message:          $r->message,
            tags:             $r->tags,
            paranoia:         $r->paranoia,
            category:         $r->category,
            setvars:          $r->setvars,
            chain:            $children,
            capture:          $r->capture,
            skipAfter:        $r->skipAfter,
            multiMatch:       $r->multiMatch,
            warnings:         $r->warnings,
            logdata:          $r->logdata,
            suppressRuleIds:  $r->suppressRuleIds,
            suppressRuleTags: $r->suppressRuleTags,
        );
    }

    /**
     * @return array<int, string> Map of original-line-number => statement
     */
    private function joinContinuationLines(string $contents): array
    {
        $lines = preg_split('/\r\n|\n|\r/', $contents) ?: [];
        $out = [];
        $buffer = '';
        $startLine = 0;
        foreach ($lines as $i => $line) {
            $lineNo = $i + 1;
            $trim = rtrim($line);
            if ($buffer === '') {
                $startLine = $lineNo;
            }

            if (str_ends_with($trim, '\\')) {
                $buffer .= substr($trim, 0, -1) . ' ';
                continue;
            }

            $buffer .= $trim;
            $out[$startLine] = $buffer;
            $buffer = '';
        }

        if ($buffer !== '') {
            $out[$startLine] = $buffer;
        }

        return $out;
    }

    /**
     * Extract the marker name from a SecMarker directive body, which may be
     * bare (`SecMarker END-FOO`) or quoted (`SecMarker "END-FOO"`).
     */
    private function markerName(string $rest): string
    {
        $tokens = $this->tokenize(trim($rest));
        return $tokens[0] ?? '';
    }

    private function readWord(string $s): string
    {
        $i = 0;
        $len = strlen($s);
        while ($i < $len && !ctype_space($s[$i])) {
            $i++;
        }

        return substr($s, 0, $i);
    }

    /**
     * @param bool $isContinuation True when this SecRule is a chain continuation.
     *        Continuations carry no id of their own — requiring one drops the
     *        real condition and lets the next rule slide into its place.
     */
    private function parseSecRule(string $body, string $sourceFile, int $line, string $category, bool $isContinuation = false): ?RuleParseState
    {
        $tokens = $this->tokenize($body);
        if (count($tokens) < 2) {
            throw new ParseException('SecRule needs at least targets and operator');
        }

        $targets = $this->parseTargets($tokens[0]);
        $operatorRaw = $tokens[1];

        [$operator, $operatorArgument, $operatorNegated, $supported] = $this->parseOperator($operatorRaw, $sourceFile, $line);
        if (!$supported) {
            $this->warnings[] = sprintf(
                "%s:%d — unsupported operator '@%s', skipping %s",
                $sourceFile,
                $line,
                $operator,
                $isContinuation ? 'chained rule' : 'rule',
            );
            return null;
        }

        $actionsRaw = $tokens[2] ?? '';
        $parsedActions    = $this->parseActions($actionsRaw);

        if (!$isContinuation && $parsedActions->id === 0) {
            $this->warnings[] = sprintf('%s:%d — SecRule has no id, skipping rule', $sourceFile, $line);
            return null;
        }

        $this->warnUnsupportedActions($parsedActions, $sourceFile, $line);

        // Continuations should not declare an id. One that does means either
        // the file is unusual or the parser has lost sync with the chain.
        if ($isContinuation && $parsedActions->id !== 0) {
            $this->warnings[] = sprintf(
                '%s:%d — chain continuation unexpectedly declares id:%d; treating it as a continuation',
                $sourceFile,
                $line,
                $parsedActions->id,
            );
        }

        $parsedRule = new ParsedRule(
            id:               $parsedActions->id,
            phase:            $parsedActions->phase,
            operator:         $operator,
            operatorArgument: $operatorArgument,
            operatorNegated:  $operatorNegated,
            targets:          $targets,
            transforms:       $parsedActions->transforms,
            action:           $parsedActions->action,
            severity:         strtolower($parsedActions->severity),
            message:          $parsedActions->message,
            tags:             $parsedActions->tags,
            paranoia:         $this->paranoiaFromTags($parsedActions->tags),
            category:         $category,
            setvars:          $parsedActions->setvars,
            chain:            [],
            capture:          $parsedActions->capture,
            skipAfter:        $parsedActions->skipAfter,
            multiMatch:       $parsedActions->multiMatch,
            warnings:         [],
            logdata:          $parsedActions->logdata,
            suppressRuleIds:  $parsedActions->suppressRuleIds,
            suppressRuleTags: $parsedActions->suppressRuleTags,
        );

        return new RuleParseState($parsedRule, $parsedActions->chain);
    }

    /**
     * Top-level tokeniser: split a SecRule body into [targets, operator, actions]
     * respecting double-quoted strings.
     *
     * @return array<int, string>
     */
    private function tokenize(string $body): array
    {
        $tokens = [];
        $len = strlen($body);
        $i = 0;
        while ($i < $len) {
            while ($i < $len && ctype_space($body[$i])) {
                $i++;
            }

            if ($i >= $len) {
                break;
            }

            if ($body[$i] === '"') {
                $i++;
                $start = $i;
                while ($i < $len) {
                    if ($body[$i] === '\\' && $i + 1 < $len) {
                        $i += 2;
                        continue;
                    }

                    if ($body[$i] === '"') {
                        break;
                    }

                    $i++;
                }

                $tokens[] = $this->unescape(substr($body, $start, $i - $start));
                if ($i < $len) {
                    $i++;
                }
            } else {
                $start = $i;
                while ($i < $len && !ctype_space($body[$i])) {
                    $i++;
                }

                $tokens[] = substr($body, $start, $i - $start);
            }
        }

        return $tokens;
    }

    private function unescape(string $s): string
    {
        return str_replace(['\\"', '\\\\'], ['"', '\\'], $s);
    }

    /**
     * Parse the |-separated target list (ARGS, !ARGS:foo, &ARGS, ARGS:/regex/).
     *
     * @return array<int, array<string, mixed>>
     */
    private function parseTargets(string $raw): array
    {
        $out = [];
        foreach (explode('|', $raw) as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }

            $negated = false;
            $count   = false;
            if ($part[0] === '!') {
                $negated = true;
                $part = substr($part, 1);
            }

            if ($part !== '' && $part[0] === '&') {
                $count = true;
                $part = substr($part, 1);
            }

            $collection = $part;
            $selector   = null;
            $regex      = false;
            $colon = strpos($part, ':');
            if ($colon !== false) {
                $collection = substr($part, 0, $colon);
                $selector   = substr($part, $colon + 1);
                if ($selector !== '' && $selector[0] === '/' && str_ends_with($selector, '/')) {
                    $selector = substr($selector, 1, -1);
                    $regex = true;
                }
            }

            $out[] = [
                'collection' => $collection,
                'selector'   => $selector,
                'negated'    => $negated,
                'count'      => $count,
                'regex'      => $regex,
            ];
        }

        return $out;
    }

    /**
     * @return array{0:string,1:string,2:bool,3:bool} [name, argument, negated, supported]
     */
    private function parseOperator(string $raw, string $sourceFile, int $line): array
    {
        $raw = trim($raw);
        $negated = false;
        if (str_starts_with($raw, '!')) {
            $negated = true;
            $raw = ltrim(substr($raw, 1));
        }

        if (!str_starts_with($raw, '@')) {
            return ['rx', $raw, $negated, true];
        }

        $space = strpos($raw, ' ');
        $name  = $space === false ? substr($raw, 1) : substr($raw, 1, $space - 1);
        $arg   = $space === false ? '' : ltrim(substr($raw, $space + 1));

        // @pmFromFile loads phrases from a sibling .data file. Inline the
        // phrase list newline-separated and route to the @pmf operator
        // (preserves phrases that contain spaces; @pm splits on whitespace).
        if (strcasecmp($name, 'pmFromFile') === 0 || strcasecmp($name, 'pmf') === 0) {
            $phrases = $this->loadPmFile($arg, $sourceFile, $line);
            if ($phrases !== null) {
                return ['pmf', $phrases, $negated, true];
            }
        }

        $supported = in_array($name, self::SUPPORTED_OPERATORS, true);
        return [$name, $arg, $negated, $supported];
    }

    /**
     * Read a @pmFromFile data file and return its phrases newline-separated,
     * ready to feed @pmf. Returns null if the file is not readable or not
     * inside the data-file directory, so the caller records a parser warning
     * and the rule is skipped.
     *
     * The filename is rule text, and bin/refresh-crs parses a freshly
     * downloaded CRS release, so it is not trusted input. Two ways it can
     * point outside the ruleset, both closed here:
     *
     *   - a path in the rule (`@pmFromFile ../../../../etc/passwd`). CRS keeps
     *     .data files as siblings of the .conf referencing them, so no
     *     legitimate rule needs a path at all. Anything that is not a bare
     *     filename is refused rather than normalised: passing it through
     *     basename() would silently redirect the read onto a sibling that
     *     happens to share the last segment, which is a different surprise
     *     rather than none.
     *   - a symlink inside the directory pointing out of it. The archive is
     *     attacker-controlled in the threat model that makes the first case
     *     interesting, and tar carries symlinks, so a bare filename is not on
     *     its own proof the read stays inside. realpath() settles it.
     *
     * Either way the contents would otherwise be inlined into rules/*.json and
     * rules/compiled.php, which the weekly workflow commits and opens a PR for
     * against a public repository.
     */
    private function loadPmFile(string $filename, string $sourceFile, int $line): ?string
    {
        $filename = trim($filename);
        if ($filename === '' || $this->dataFileDir === null) {
            return null;
        }

        if ($filename !== basename($filename)) {
            $this->warnings[] = sprintf(
                "%s:%d — @pmFromFile '%s' is not a bare filename; refusing to read outside %s",
                $sourceFile,
                $line,
                $filename,
                $this->dataFileDir,
            );
            return null;
        }

        $path = $this->dataFileDir . '/' . $filename;
        if (!is_file($path)) {
            return null;
        }

        if (!$this->isInsideDataFileDir($path)) {
            $this->warnings[] = sprintf(
                "%s:%d — @pmFromFile '%s' resolves outside %s (symlink?); refusing to read it",
                $sourceFile,
                $line,
                $filename,
                $this->dataFileDir,
            );
            return null;
        }

        $phrases = [];
        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            if (str_starts_with($line, '#')) {
                continue;
            }

            $phrases[] = $line;
        }

        return $phrases === [] ? null : implode("\n", $phrases);
    }

    /**
     * Whether $path resolves to a file genuinely inside $dataFileDir, after
     * symlinks are followed on both sides.
     */
    private function isInsideDataFileDir(string $path): bool
    {
        $realPath = realpath($path);
        $realDir  = realpath((string) $this->dataFileDir);

        if ($realPath === false || $realDir === false) {
            return false;
        }

        return str_starts_with($realPath, rtrim($realDir, '/') . '/');
    }

    /**
     * Record the actions a rule declared that this engine recognises but does
     * not implement, so they land in manifest.json alongside the unsupported
     * operators rather than being dropped in silence.
     *
     * The rule still runs — these actions change behaviour at the margins
     * rather than defining the detection — so this is a warning, not a skip.
     * The point is that a CRS release leaning harder on ctl becomes visible in
     * the refresh PR's warning count instead of quietly diverging.
     */
    private function warnUnsupportedActions(ParsedActions $parsedActions, string $sourceFile, int $line): void
    {
        // Chain continuations carry no id of their own, so naming one "rule 0"
        // sends a reader looking for a rule that does not exist.
        $subject = $parsedActions->id === 0
            ? 'a chain continuation'
            : 'rule ' . $parsedActions->id;

        foreach ($parsedActions->unsupportedActions as $action) {
            $this->warnings[] = sprintf(
                '%s:%d — %s uses unsupported action `%s`; it is ignored and the rule may behave '
                . 'differently than under ModSecurity',
                $sourceFile,
                $line,
                $subject,
                $action,
            );
        }
    }

    /**
     * Recognise the ctl: forms this engine implements, returning true when the
     * value was consumed.
     *
     * ModSecurity scopes a ctl action to the current transaction and to rules
     * evaluated after it, which is exactly how CRS uses it: a cheap guard rule
     * fires early and switches off a later rule that would otherwise misfire on
     * that shape of traffic.
     *
     * ruleRemoveById accepts a single id or an inclusive range (`1-99`), and a
     * space-separated list of either.
     */
    private function parseCtl(string $value, ParsedActions $parsedActions): bool
    {
        $eq = strpos($value, '=');
        if ($eq === false) {
            return false;
        }

        $directive = strtolower(trim(substr($value, 0, $eq)));
        $argument  = trim(substr($value, $eq + 1));

        if ($directive === 'ruleremovebytag') {
            if ($argument === '') {
                return false;
            }

            $parsedActions->suppressRuleTags[] = $argument;
            return true;
        }

        if ($directive !== 'ruleremovebyid') {
            return false;
        }

        $ids = [];
        foreach (preg_split('/[\s,]+/', $argument) ?: [] as $entry) {
            if ($entry === '') {
                continue;
            }

            if (preg_match('/^(\d+)-(\d+)$/', $entry, $m) === 1) {
                $from = (int) $m[1];
                $to   = (int) $m[2];
                if ($from > $to) {
                    return false;
                }

                // A CRS id block is 100 wide; anything vastly larger is a
                // malformed rule rather than an intent to disable the ruleset.
                if ($to - $from > 10000) {
                    return false;
                }

                for ($id = $from; $id <= $to; $id++) {
                    $ids[] = $id;
                }

                continue;
            }

            if (!ctype_digit($entry)) {
                return false;
            }

            $ids[] = (int) $entry;
        }

        if ($ids === []) {
            return false;
        }

        foreach ($ids as $id) {
            $parsedActions->suppressRuleIds[] = $id;
        }

        return true;
    }

    private function parseActions(string $raw): ParsedActions
    {
        $parsedActions = new ParsedActions();

        foreach ($this->splitActions($raw) as $action) {
            $action = trim($action);
            if ($action === '') {
                continue;
            }

            $colon = strpos($action, ':');
            $name = $colon === false ? $action : substr($action, 0, $colon);
            $value = $colon === false ? null : trim(substr($action, $colon + 1));
            if ($value !== null && $value !== '' && $value[0] === "'" && str_ends_with($value, "'")) {
                $value = substr($value, 1, -1);
            }

            switch (strtolower($name)) {
                case 'id':
                    $parsedActions->id = (int) ($value ?? '0');
                    break;
                case 'phase':
                    $parsedActions->phase = $this->parsePhase($value ?? '2');
                    break;
                case 'block':
                case 'deny':
                case 'drop':
                    $parsedActions->action = strtolower($name);
                    break;
                case 'pass':
                case 'allow':
                    $parsedActions->action = 'pass';
                    break;
                case 'chain':
                    $parsedActions->chain = true;
                    break;
                case 'capture':
                    $parsedActions->capture = true;
                    break;
                case 'multimatch':
                    $parsedActions->multiMatch = true;
                    break;
                case 't':
                    if ($value !== null) {
                        $parsedActions->transforms[] = $value;
                    }

                    break;
                case 'msg':
                    $parsedActions->message = $value ?? '';
                    break;
                case 'logdata':
                    $parsedActions->logdata = $value;
                    break;
                case 'severity':
                    if ($value !== null) {
                        $parsedActions->severity = $value;
                    }

                    break;
                case 'tag':
                    if ($value !== null) {
                        $parsedActions->tags[] = $value;
                    }

                    break;
                case 'setvar':
                    if ($value !== null) {
                        $parsedActions->setvars[] = $this->parseSetvar($value);
                    }

                    break;
                case 'skipafter':
                    $parsedActions->skipAfter = $value;
                    break;
                // Recognised, not implemented, and consequential: each of these
                // changes what a rule does under ModSecurity, so a rule using
                // one behaves differently here. Collected for the caller to
                // report against the rule id.
                //
                // ctl is the one that matters most — ctl:requestBodyProcessor
                // changes what gets parsed and inspected, and
                // ctl:ruleRemoveTargetById changes which rules apply to which
                // targets. The rest imply cross-request state this engine does
                // not model at all.
                case 'ctl':
                    // Two forms are implemented, because CRS relies on them to
                    // switch a rule off for traffic it knows will trip it —
                    // 920539 exists solely to disable 920540 on JSON bodies,
                    // where \uXXXX is ordinary string escaping rather than an
                    // evasion attempt. Anything else still warns.
                    if ($value !== null && $this->parseCtl($value, $parsedActions)) {
                        break;
                    }

                    $parsedActions->unsupportedActions[] = $value === null
                        ? 'ctl'
                        : 'ctl:' . $value;
                    break;
                case 'expirevar':
                case 'deprecatevar':
                case 'initcol':
                case 'setsid':
                case 'setuid':
                case 'setrsc':
                    $parsedActions->unsupportedActions[] = $value === null
                        ? strtolower($name)
                        : strtolower($name) . ':' . $value;
                    break;
                // Metadata and audit-log hints the engine has no use for. Inert
                // by nature rather than unimplemented, so warning about them
                // would bury the entries above under noise on every rule.
                case 'ver':
                case 'rev':
                case 'maturity':
                case 'accuracy':
                case 'sanitisearg':
                case 'sanitiserequestheader':
                case 'nolog':
                case 'log':
                case 'auditlog':
                case 'noauditlog':
                default:
                    break;
            }
        }

        return $parsedActions;
    }

    /**
     * @return array<int, string>
     */
    private function splitActions(string $raw): array
    {
        $out = [];
        $len = strlen($raw);
        $i = 0;
        $buf = '';
        $inQuote = false;
        while ($i < $len) {
            $c = $raw[$i];
            if ($c === '\\' && $i + 1 < $len) {
                $buf .= $c . $raw[$i + 1];
                $i += 2;
                continue;
            }

            if ($c === "'") {
                $inQuote = !$inQuote;
                $buf .= $c;
                $i++;
                continue;
            }

            if ($c === ',' && !$inQuote) {
                $out[] = $buf;
                $buf = '';
                $i++;
                continue;
            }

            $buf .= $c;
            $i++;
        }

        if ($buf !== '') {
            $out[] = $buf;
        }

        return $out;
    }

    private function parsePhase(string $value): int
    {
        return match (strtolower(trim($value))) {
            'request', '1' => 1,
            'request_body', '2' => 2,
            'response', '3' => 3,
            'response_body', '4' => 4,
            'logging', '5' => 5,
            default => (int) $value ?: 2,
        };
    }

    /**
     * @return array{name: string, op: string, value: string}
     */
    private function parseSetvar(string $value): array
    {
        if (str_starts_with($value, '!')) {
            return ['name' => substr($value, 1), 'op' => 'unset', 'value' => ''];
        }

        $eq = strpos($value, '=');
        if ($eq === false) {
            return ['name' => $value, 'op' => '=', 'value' => '1'];
        }

        $name = substr($value, 0, $eq);
        $rhs  = substr($value, $eq + 1);
        $op = '=';
        if ($rhs !== '' && $rhs[0] === '+') {
            $op = '+';
            $rhs = substr($rhs, 1);
        } elseif ($rhs !== '' && $rhs[0] === '-') {
            $op = '-';
            $rhs = substr($rhs, 1);
        }

        // %{...} on the right-hand side is left intact for the evaluator to
        // expand per request. Resolving it here collapsed every reference the
        // parser did not recognise to a literal 0, which is what made the 949
        // aggregation rules add nothing and left anomaly blocking dead.
        return ['name' => $name, 'op' => $op, 'value' => $rhs];
    }

    /**
     * @param array<int, string> $tags
     */
    private function paranoiaFromTags(array $tags): int
    {
        foreach ($tags as $tag) {
            if (preg_match('#paranoia-level/(\d+)#', $tag, $m)) {
                return (int) $m[1];
            }
        }

        return 1;
    }

    /**
     * CRS numbers its rule files, and the number is the only unambiguous part
     * of the name. Matching on words in the filename collides badly: "rce"
     * appears inside "enfoRCEment", so both METHOD-ENFORCEMENT and
     * PROTOCOL-ENFORCEMENT were filed as remote code execution, and "php" and
     * "java" match the RESPONSE data-leakage files as well as the REQUEST
     * attack files.
     *
     * 948 is this engine's own supplemental file, not CRS — see supplemental/.
     *
     * @var array<int, string>
     */
    private const FILE_CATEGORIES = [
        911 => 'method_enforcement',
        913 => 'scanner',
        920 => 'protocol_enforcement',
        921 => 'protocol_attack',
        922 => 'multipart',
        930 => 'lfi',
        931 => 'rfi',
        932 => 'rce',
        933 => 'php',
        934 => 'generic',
        941 => 'xss',
        942 => 'sqli',
        943 => 'session_fixation',
        944 => 'java',
        948 => 'sqli',
        949 => 'blocking_evaluation',
        950 => 'response_leak',
        951 => 'response_leak_sql',
        952 => 'response_leak_java',
        953 => 'response_leak_php',
        954 => 'response_leak_iis',
        955 => 'web_shell',
        956 => 'response_leak_ruby',
        959 => 'blocking_evaluation',
        980 => 'correlation',
    ];

    private function categoryFromFilename(string $filename): string
    {
        $base = strtolower(basename($filename, '.conf'));

        if (preg_match('/^(?:request|response)-(\d{3})-/', $base, $m) === 1) {
            $known = self::FILE_CATEGORIES[(int) $m[1]] ?? null;
            if ($known !== null) {
                return $known;
            }
        }

        return $this->categoryFromKeywords($base);
    }

    /**
     * Fallback for a file CRS has added since this map was written, or for a
     * custom ruleset that does not follow the numbering. Ordered most-specific
     * first, and response-side leakage names are checked before the bare
     * attack-type names they contain.
     */
    private function categoryFromKeywords(string $base): string
    {
        return match (true) {
            str_contains($base, 'data-leakages-sql')    => 'response_leak_sql',
            str_contains($base, 'data-leakages-java')   => 'response_leak_java',
            str_contains($base, 'data-leakages-php')    => 'response_leak_php',
            str_contains($base, 'data-leakages-iis')    => 'response_leak_iis',
            str_contains($base, 'data-leakages-ruby')   => 'response_leak_ruby',
            str_contains($base, 'data-leakages')        => 'response_leak',
            str_contains($base, 'web-shells')           => 'web_shell',
            str_contains($base, 'correlation')          => 'correlation',
            str_contains($base, 'blocking-evaluation')  => 'blocking_evaluation',
            str_contains($base, 'session-fixation')     => 'session_fixation',
            str_contains($base, 'protocol-enforcement') => 'protocol_enforcement',
            str_contains($base, 'protocol-attack')      => 'protocol_attack',
            str_contains($base, 'method-enforcement')   => 'method_enforcement',
            str_contains($base, 'scanner')              => 'scanner',
            str_contains($base, 'multipart')            => 'multipart',
            str_contains($base, 'sqli')                 => 'sqli',
            str_contains($base, 'xss')                  => 'xss',
            str_contains($base, 'lfi')                  => 'lfi',
            str_contains($base, 'rfi')                  => 'rfi',
            str_contains($base, 'attack-rce')           => 'rce',
            str_contains($base, 'attack-php')           => 'php',
            str_contains($base, 'attack-java')          => 'java',
            str_contains($base, 'generic')              => 'generic',
            default                                     => 'misc',
        };
    }
}

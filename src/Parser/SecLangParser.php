<?php

declare(strict_types=1);

namespace Kanopi\Crs\Parser;

use Kanopi\Crs\Exception\ParseException;

/**
 * Parses ModSecurity SecLang .conf files into ParsedRule objects.
 *
 * Scope is intentionally limited to the subset used by CRS REQUEST-*
 * rule files. Out-of-scope (parsed but ignored, with a warning):
 *   - @detectSQLi / @detectXSS  (require libinjection)
 *   - ctl:*                     (engine controls beyond ruleEngine)
 *   - audit log directives
 *   - XML: targets              (no XML body parser in v1)
 */
final class SecLangParser
{
    private const SUPPORTED_OPERATORS = [
        'rx', 'pm', 'pmf', 'beginsWith', 'endsWith', 'contains', 'containsWord',
        'streq', 'eq', 'gt', 'lt', 'ge', 'le', 'within', 'ipMatch',
        'validateByteRange', 'validateUrlEncoding', 'validateUtf8Encoding',
    ];

    /** Default CRS anomaly-score constants used when a rule references them. */
    private const ANOMALY_DEFAULTS = [
        'tx.critical_anomaly_score' => 5,
        'tx.error_anomaly_score'    => 4,
        'tx.warning_anomaly_score'  => 3,
        'tx.notice_anomaly_score'   => 2,
    ];

    /** @var array<int, string> */
    public array $warnings = [];

    /** @var array<int, int> */
    public array $skippedRules = [];

    /**
     * Directory containing .data files referenced by @pmFromFile.
     * Auto-populated from the .conf file's directory in parseFile().
     */
    private ?string $dataFileDir = null;

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

            if (strcasecmp($directive, 'SecAction') === 0) {
                $this->dropUnterminatedChain($pendingChainParent, $pendingChain, $sourceFile, $line, 'SecAction');
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

        return $rules;
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

        [$operator, $operatorArgument, $operatorNegated, $supported] = $this->parseOperator($operatorRaw);
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
    private function parseOperator(string $raw): array
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
            $phrases = $this->loadPmFile($arg);
            if ($phrases !== null) {
                return ['pmf', $phrases, $negated, true];
            }
        }

        $supported = in_array($name, self::SUPPORTED_OPERATORS, true);
        return [$name, $arg, $negated, $supported];
    }

    /**
     * Read a @pmFromFile data file and return its phrases as a single
     * space-separated string ready to feed @pm. Returns null if the file
     * is not findable so the caller records a parser warning.
     */
    private function loadPmFile(string $filename): ?string
    {
        $filename = trim($filename);
        if ($filename === '' || $this->dataFileDir === null) {
            return null;
        }

        $path = $this->dataFileDir . '/' . $filename;
        if (!is_file($path)) {
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
                case 'ver':
                case 'rev':
                case 'maturity':
                case 'accuracy':
                case 'ctl':
                case 'expirevar':
                case 'deprecatevar':
                case 'initcol':
                case 'sanitisearg':
                case 'sanitiserequestheader':
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

        $rhs = $this->resolveVarRefs($rhs);
        return ['name' => $name, 'op' => $op, 'value' => $rhs];
    }

    private function resolveVarRefs(string $value): string
    {
        return (string) preg_replace_callback(
            '/%\{([^}]+)\}/',
            static function (array $m): string {
                $key = strtolower($m[1]);
                return (string) (self::ANOMALY_DEFAULTS[$key] ?? 0);
            },
            $value
        );
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

    private function categoryFromFilename(string $filename): string
    {
        $base = strtolower(basename($filename, '.conf'));
        return match (true) {
            str_contains($base, 'sqli')             => 'sqli',
            str_contains($base, 'xss')              => 'xss',
            str_contains($base, 'lfi')              => 'lfi',
            str_contains($base, 'rfi')              => 'rfi',
            str_contains($base, 'rce')              => 'rce',
            str_contains($base, 'php')              => 'php',
            str_contains($base, 'java')             => 'java',
            str_contains($base, 'session-fixation') => 'session_fixation',
            str_contains($base, 'protocol-attack')  => 'protocol_attack',
            str_contains($base, 'protocol-enforcement') => 'protocol_enforcement',
            str_contains($base, 'method-enforcement')    => 'method_enforcement',
            str_contains($base, 'scanner')          => 'scanner',
            str_contains($base, 'multipart')        => 'multipart',
            str_contains($base, 'generic')          => 'generic',
            str_contains($base, 'data-leakages-sql')  => 'response_leak_sql',
            str_contains($base, 'data-leakages-java') => 'response_leak_java',
            str_contains($base, 'data-leakages-php')  => 'response_leak_php',
            str_contains($base, 'data-leakages-iis')  => 'response_leak_iis',
            str_contains($base, 'data-leakages')      => 'response_leak',
            str_contains($base, 'web-shells')         => 'web_shell',
            str_contains($base, 'correlation')        => 'correlation',
            default                                  => 'misc',
        };
    }
}

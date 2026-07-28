<?php

declare(strict_types=1);

namespace Kanopi\Crs\Parser;

/**
 * Internal DTO holding the parsed contents of a SecRule's action list.
 * Used only inside the parser; CompiledRule is the public runtime form.
 *
 * @internal
 */
final class ParsedActions
{
    /**
     * @param array<int, string> $transforms
     * @param array<int, string> $tags
     * @param array<int, array{name: string, op: string, value: string}> $setvars
     * @param array<int, int> $suppressRuleIds Rule IDs this rule switches off
     *        for the rest of the transaction, from ctl:ruleRemoveById.
     * @param array<int, string> $suppressRuleTags Tags this rule switches off
     *        for the rest of the transaction, from ctl:ruleRemoveByTag.
     * @param array<int, string> $unsupportedActions Actions recognised but not
     *        implemented, which change what a rule does — the caller turns
     *        these into parser warnings once it knows the rule id. Metadata the
     *        engine has no use for (ver, rev, maturity, ...) is not collected:
     *        it is genuinely inert, and warning about it would bury the
     *        entries that mean the rule behaves differently here.
     */
    public function __construct(
        public int $id = 0,
        public int $phase = 2,
        public string $action = 'pass',
        public string $severity = 'notice',
        public string $message = '',
        public array $transforms = [],
        public array $tags = [],
        public array $setvars = [],
        public bool $capture = false,
        public bool $multiMatch = false,
        public bool $chain = false,
        public ?string $skipAfter = null,
        public ?string $logdata = null,
        public array $unsupportedActions = [],
        public array $suppressRuleIds = [],
        public array $suppressRuleTags = [],
    ) {
    }
}

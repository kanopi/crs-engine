<?php

declare(strict_types=1);

namespace Kanopi\Crs\Parser;

/**
 * Internal DTO returned by SecLangParser::parseSecRule(). Holds the
 * parsed rule plus a flag telling parseString() whether to expect a
 * chained follow-up rule on the next statement.
 *
 * @internal
 */
final class RuleParseState
{
    public function __construct(
        public readonly ParsedRule $rule,
        public readonly bool $hasChainFollow,
    ) {
    }
}

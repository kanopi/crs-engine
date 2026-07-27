<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

/**
 * Phrase match — ModSecurity's case-insensitive substring search across a
 * whitespace-separated list of phrases. See PhraseSet for how the list is
 * prepared and why.
 */
final class PmOperator implements OperatorInterface
{
    /** @var array<string, PhraseSet> */
    private static array $phraseCache = [];

    public function name(): string
    {
        return 'pm';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        $phrases = self::$phraseCache[$argument]
            ??= PhraseSet::fromWhitespaceList($argument);

        $hit = $phrases->firstMatch($value);

        return $hit === null ? OperatorMatch::miss() : OperatorMatch::hit($hit);
    }
}

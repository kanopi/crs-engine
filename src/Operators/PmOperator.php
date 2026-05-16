<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

/**
 * Phrase match — ModSecurity's case-insensitive substring search across a
 * whitespace-separated list of phrases. Real ModSecurity uses Aho-Corasick;
 * we use stripos in a loop and break on first hit. Good enough for typical
 * CRS phrase lists (tens to low hundreds of phrases); revisit if a specific
 * rule blows the perf budget.
 */
final class PmOperator implements OperatorInterface
{
    /** @var array<string, array<int, string>> */
    private static array $phraseCache = [];

    public function name(): string
    {
        return 'pm';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        $phrases = self::$phraseCache[$argument] ?? null;
        if ($phrases === null) {
            $phrases = preg_split('/\s+/', trim($argument)) ?: [];
            self::$phraseCache[$argument] = $phrases;
        }

        $haystack = strtolower($value);
        foreach ($phrases as $phrase) {
            if ($phrase === '') {
                continue;
            }

            if (str_contains($haystack, strtolower($phrase))) {
                return OperatorMatch::hit($phrase);
            }
        }

        return OperatorMatch::miss();
    }
}

<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

/**
 * @pmf — phrase match from file. Same case-insensitive substring search as
 * @pm but the list is newline-separated, which preserves phrases containing
 * spaces such as "Mozilla/5.0 (compatible; Panoptic".
 *
 * The parser inlines @pmFromFile's .data file contents and routes the rule
 * here. Some CRS lists are large — 953100 carries about 10,600 phrases — so
 * see PhraseSet for how they are filtered before the substring search.
 */
final class PmfOperator implements OperatorInterface
{
    /** @var array<string, PhraseSet> */
    private static array $phraseCache = [];

    public function name(): string
    {
        return 'pmf';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        $phrases = self::$phraseCache[$argument]
            ??= PhraseSet::fromLines($argument);

        $hit = $phrases->firstMatch($value);

        return $hit === null ? OperatorMatch::miss() : OperatorMatch::hit($hit);
    }
}

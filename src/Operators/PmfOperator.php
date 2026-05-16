<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

/**
 * @pmf — phrase match from file. Same case-insensitive substring search
 * as @pm but splits the argument on newlines (not whitespace), preserving
 * phrases that contain spaces such as "Mozilla/5.0 (compatible; Panoptic".
 *
 * The parser inlines @pmFromFile's .data file contents as a newline-
 * separated phrase list, then routes the rule to this operator.
 */
final class PmfOperator implements OperatorInterface
{
    /** @var array<string, array<int, string>> */
    private static array $phraseCache = [];

    public function name(): string
    {
        return 'pmf';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        $phrases = self::$phraseCache[$argument] ?? null;
        if ($phrases === null) {
            $phrases = [];
            foreach (preg_split('/\r\n|\n|\r/', $argument) ?: [] as $line) {
                $line = trim($line);
                if ($line !== '') {
                    $phrases[] = strtolower($line);
                }
            }

            self::$phraseCache[$argument] = $phrases;
        }

        $haystack = strtolower($value);
        foreach ($phrases as $phrase) {
            if (str_contains($haystack, $phrase)) {
                return OperatorMatch::hit($phrase);
            }
        }

        return OperatorMatch::miss();
    }
}

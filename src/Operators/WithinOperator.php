<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

/**
 * @within matches when the runtime value is one of the whitespace-separated
 * entries in the static argument list.
 *
 * ModSecurity implements @within as a plain substring test — "is the value
 * found anywhere inside the argument" — and CRS compensates by delimiting both
 * sides so a substring hit can only land on a whole entry: 920420 builds its
 * needle as '|%{tx.0}|' against '|text/xml| |application/json| ...', 920440
 * builds '.%{tx.1}/' against '.bak/ .old/ ...', 920450 builds '/%{tx.0}/'
 * against '/proxy/ /lock-token/ ...'.
 *
 * That trick only holds where the rule author applied it. It is absent from the
 * allow-lists carrying bare values, and there a substring test is a hole: with
 * tx.allowed_methods = 'GET HEAD POST OPTIONS', the method `OST` is a substring
 * of POST, so `!@within` did not fire and method enforcement (911100) was
 * bypassed. `ET`, `T` and `HEA` behave the same way, and because
 * str_contains($haystack, '') is true in PHP, so did an empty value — on every
 * @within rule at once.
 *
 * Comparing complete entries closes that without breaking the delimiter-wrapped
 * rules: their needles are already exactly one entry of the list, so an exact
 * match succeeds wherever the substring match legitimately did. This is a
 * deliberate divergence from ModSecurity, in the direction of what the rules
 * mean rather than what the operator historically did. All nine @within usages
 * in the shipped ruleset are covered by WithinOperatorTest.
 *
 * Case-sensitive, as upstream is; rules needing otherwise apply t:lowercase to
 * the target, and the seeded lists are lowercase to match.
 */
final class WithinOperator implements OperatorInterface
{
    /**
     * Entry set per argument, so the list is split once rather than on every
     * evaluation. Arguments arrive already macro-expanded, and those expansions
     * are stable for the life of the process.
     *
     * @var array<string, array<string, true>>
     */
    private static array $entryCache = [];

    public function name(): string
    {
        return 'within';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        // An empty value is not a member of any list. Under the substring test
        // it matched everything, which left the negated form unable to fire on
        // a missing method, protocol or charset.
        if ($value === '') {
            return OperatorMatch::miss();
        }

        $entries = self::$entryCache[$argument] ?? null;
        if ($entries === null) {
            $entries = [];
            foreach (preg_split('/\s+/', trim($argument)) ?: [] as $entry) {
                if ($entry !== '') {
                    $entries[$entry] = true;
                }
            }

            self::$entryCache[$argument] = $entries;
        }

        return isset($entries[$value])
            ? OperatorMatch::hit($value)
            : OperatorMatch::miss();
    }
}

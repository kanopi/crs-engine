<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class RxOperator implements OperatorInterface
{
    /**
     * Cache compiled PCRE delimiters per pattern. Even with opcache, this
     * saves repeated string concat on hot rules.
     *
     * @var array<string, string>
     */
    private static array $compiled = [];

    /**
     * PCRE failures that depend on the subject rather than the pattern, so an
     * attacker can provoke them with a large or awkward payload. These are the
     * ones that must not be reported as "no attack found".
     *
     * A compile failure (PREG_INTERNAL_ERROR) is deliberately absent: it is a
     * property of the ruleset, identical on every request, and a rule carrying
     * a broken pattern never matches anything — so it is a CI problem, not a
     * per-request one, and treating it as a runtime fault would let one bad
     * rule fail every request closed.
     *
     * @var array<int, int>
     */
    private const RESOURCE_LIMIT_ERRORS = [
        PREG_BACKTRACK_LIMIT_ERROR,
        PREG_RECURSION_LIMIT_ERROR,
        PREG_JIT_STACKLIMIT_ERROR,
    ];

    public function name(): string
    {
        return 'rx';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        $pattern = self::$compiled[$argument] ?? null;
        if ($pattern === null) {
            $pattern = '#' . str_replace('#', '\\#', $argument) . '#sS';
            self::$compiled[$argument] = $pattern;
        }

        $matches = [];
        $result = @preg_match($pattern, $value, $matches);

        // preg_match() returns false — not 0 — when it gives up on a resource
        // limit. Folding that into a miss made an aborted regex look exactly
        // like a clean evaluation, so a rule could be skipped silently and the
        // verdict would report the request as carrying no attack. The subject
        // is attacker-controlled, which makes the difference security-relevant
        // rather than cosmetic.
        if ($result === false) {
            $error = preg_last_error();

            return in_array($error, self::RESOURCE_LIMIT_ERRORS, true)
                ? OperatorMatch::error(preg_last_error_msg())
                : OperatorMatch::miss();
        }

        if ($result === 0) {
            return OperatorMatch::miss();
        }

        // Numbered groups only; the evaluator copies them to TX:0..TX:9 when
        // the rule carries `capture`.
        $captures = [];
        foreach ($matches as $index => $group) {
            if (is_int($index)) {
                $captures[$index] = $group;
            }
        }

        return OperatorMatch::hit($matches[0] ?? '', $captures);
    }
}

<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class ContainsWordOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'containsWord';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        $pattern = '/\b' . preg_quote($argument, '/') . '\b/i';
        $result  = @preg_match($pattern, $value);

        // Same fail-open as @rx had: false means the match was abandoned, not
        // that the word is absent. The pattern is preg_quote()d so it cannot
        // fail to compile; anything false here is a subject-driven limit.
        if ($result === false) {
            return OperatorMatch::error(preg_last_error_msg());
        }

        return $result === 1
            ? OperatorMatch::hit($argument)
            : OperatorMatch::miss();
    }
}

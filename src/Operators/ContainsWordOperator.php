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
        if (preg_match($pattern, $value)) {
            return OperatorMatch::hit($argument);
        }

        return OperatorMatch::miss();
    }
}

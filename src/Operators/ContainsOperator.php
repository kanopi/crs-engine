<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class ContainsOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'contains';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return str_contains($value, $argument)
            ? OperatorMatch::hit($argument)
            : OperatorMatch::miss();
    }
}

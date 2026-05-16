<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class EndsWithOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'endsWith';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return str_ends_with($value, $argument)
            ? OperatorMatch::hit($argument)
            : OperatorMatch::miss();
    }
}

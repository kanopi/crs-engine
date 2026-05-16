<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class BeginsWithOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'beginsWith';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return str_starts_with($value, $argument)
            ? OperatorMatch::hit($argument)
            : OperatorMatch::miss();
    }
}

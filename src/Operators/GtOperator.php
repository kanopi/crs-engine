<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class GtOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'gt';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return ((int) $value) > ((int) $argument)
            ? OperatorMatch::hit($value)
            : OperatorMatch::miss();
    }
}

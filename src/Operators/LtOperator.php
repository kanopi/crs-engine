<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class LtOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'lt';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return ((int) $value) < ((int) $argument)
            ? OperatorMatch::hit($value)
            : OperatorMatch::miss();
    }
}

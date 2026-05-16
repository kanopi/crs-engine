<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class GeOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'ge';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return ((int) $value) >= ((int) $argument)
            ? OperatorMatch::hit($value)
            : OperatorMatch::miss();
    }
}

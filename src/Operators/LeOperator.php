<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class LeOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'le';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return ((int) $value) <= ((int) $argument)
            ? OperatorMatch::hit($value)
            : OperatorMatch::miss();
    }
}

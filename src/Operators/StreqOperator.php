<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class StreqOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'streq';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return $argument === $value
            ? OperatorMatch::hit($value)
            : OperatorMatch::miss();
    }
}

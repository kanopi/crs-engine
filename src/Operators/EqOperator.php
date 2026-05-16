<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class EqOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'eq';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return ((int) $argument) === ((int) $value)
            ? OperatorMatch::hit($value)
            : OperatorMatch::miss();
    }
}

<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

/**
 * @within matches when the runtime value appears as a whole token in the
 * static argument list. Inverse of @contains.
 */
final class WithinOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'within';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return str_contains($argument, $value)
            ? OperatorMatch::hit($value)
            : OperatorMatch::miss();
    }
}

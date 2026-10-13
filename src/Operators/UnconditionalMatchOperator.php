<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

/**
 * Matches every value it is given. CRS uses it as a chain link whose only job
 * is to run setvars once per resolved value (922100 collects each _charset_
 * into its own TX variable this way). It still needs a value to see: a target
 * that resolves to nothing never reaches the operator, so the link fails.
 */
final class UnconditionalMatchOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'unconditionalMatch';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return OperatorMatch::hit($value);
    }
}

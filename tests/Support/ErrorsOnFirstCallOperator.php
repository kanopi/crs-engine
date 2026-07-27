<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Support;

use Kanopi\Crs\Operators\OperatorInterface;
use Kanopi\Crs\Operators\OperatorMatch;

/**
 * Fails to decide on its first call and matches on every one after, so a
 * multiMatch rule can be shown to still find a hit at a later transform step.
 */
final class ErrorsOnFirstCallOperator implements OperatorInterface
{
    private int $calls = 0;

    public function name(): string
    {
        return 'faulty';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        $this->calls++;

        return $this->calls === 1
            ? OperatorMatch::error('Backtrack limit exhausted')
            : OperatorMatch::hit($value);
    }
}

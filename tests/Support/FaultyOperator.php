<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Support;

use Kanopi\Crs\Operators\OperatorInterface;
use Kanopi\Crs\Operators\OperatorMatch;

/**
 * Always reports that it could not decide, standing in for a regex PCRE
 * abandoned on a resource limit.
 */
final class FaultyOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'faulty';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return OperatorMatch::error('Backtrack limit exhausted');
    }
}

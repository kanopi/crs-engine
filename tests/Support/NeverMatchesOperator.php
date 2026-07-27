<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Support;

use Kanopi\Crs\Operators\OperatorInterface;
use Kanopi\Crs\Operators\OperatorMatch;

/**
 * Decides cleanly every time, and always that there is nothing here. Registered
 * under the same name as FaultyOperator so a test can swap one for the other.
 */
final class NeverMatchesOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'faulty';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        return OperatorMatch::miss();
    }
}

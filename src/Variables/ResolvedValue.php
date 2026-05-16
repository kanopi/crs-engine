<?php

declare(strict_types=1);

namespace Kanopi\Crs\Variables;

/**
 * A single value extracted from the request for a target, plus a label
 * describing where it came from (used in match logging).
 */
final class ResolvedValue
{
    public function __construct(
        public readonly string $location,
        public readonly string $value,
    ) {
    }
}

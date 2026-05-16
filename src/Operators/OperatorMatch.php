<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class OperatorMatch
{
    public function __construct(
        public readonly bool $matched,
        public readonly string $matchedData = '',
    ) {
    }

    public static function miss(): self
    {
        return new self(false);
    }

    public static function hit(string $matchedData = ''): self
    {
        return new self(true, $matchedData);
    }
}

<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class LowercaseTransform implements TransformInterface
{
    public function name(): string
    {
        return 'lowercase';
    }

    public function apply(string $value): string
    {
        return mb_strtolower($value, 'UTF-8');
    }
}

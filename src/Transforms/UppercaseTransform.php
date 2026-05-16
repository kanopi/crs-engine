<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class UppercaseTransform implements TransformInterface
{
    public function name(): string
    {
        return 'uppercase';
    }

    public function apply(string $value): string
    {
        return mb_strtoupper($value, 'UTF-8');
    }
}

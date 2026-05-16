<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class TrimTransform implements TransformInterface
{
    public function name(): string
    {
        return 'trim';
    }

    public function apply(string $value): string
    {
        return trim($value);
    }
}

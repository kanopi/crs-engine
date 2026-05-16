<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class LengthTransform implements TransformInterface
{
    public function name(): string
    {
        return 'length';
    }

    public function apply(string $value): string
    {
        return (string) strlen($value);
    }
}

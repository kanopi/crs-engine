<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class RemoveWhitespaceTransform implements TransformInterface
{
    public function name(): string
    {
        return 'removeWhitespace';
    }

    public function apply(string $value): string
    {
        return (string) preg_replace('/\s+/', '', $value);
    }
}

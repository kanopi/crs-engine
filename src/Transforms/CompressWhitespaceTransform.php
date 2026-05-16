<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class CompressWhitespaceTransform implements TransformInterface
{
    public function name(): string
    {
        return 'compressWhitespace';
    }

    public function apply(string $value): string
    {
        return (string) preg_replace('/\s+/', ' ', $value);
    }
}

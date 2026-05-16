<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class ReplaceNullsTransform implements TransformInterface
{
    public function name(): string
    {
        return 'replaceNulls';
    }

    public function apply(string $value): string
    {
        return str_replace("\0", ' ', $value);
    }
}

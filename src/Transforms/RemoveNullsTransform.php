<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class RemoveNullsTransform implements TransformInterface
{
    public function name(): string
    {
        return 'removeNulls';
    }

    public function apply(string $value): string
    {
        return str_replace("\0", '', $value);
    }
}

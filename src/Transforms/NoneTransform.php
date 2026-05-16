<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * Sentinel transform meaning "reset prior transforms". The pipeline
 * treats this as a marker and clears its accumulated list. Applying it
 * directly is a no-op.
 */
final class NoneTransform implements TransformInterface
{
    public function name(): string
    {
        return 'none';
    }

    public function apply(string $value): string
    {
        return $value;
    }
}

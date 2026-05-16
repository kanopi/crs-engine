<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * Collapses path traversals (./, ../) and duplicate slashes so LFI rules
 * match regardless of how the attacker writes the path.
 */
final class NormalisePathTransform implements TransformInterface
{
    public function name(): string
    {
        return 'normalisePath';
    }

    public function apply(string $value): string
    {
        $value = (string) preg_replace('#/+#', '/', $value);
        $value = (string) preg_replace('#/\./#', '/', $value);
        while (preg_match('#[^/]+/\.\./?#', $value)) {
            $value = (string) preg_replace('#[^/]+/\.\./?#', '', $value, 1);
        }

        return $value;
    }
}

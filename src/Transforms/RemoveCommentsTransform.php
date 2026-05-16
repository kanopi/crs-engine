<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * Strips SQL-style and C-style comments so SQLi rules see through
 * attempts to insert /* * / or -- comment evasions.
 */
final class RemoveCommentsTransform implements TransformInterface
{
    public function name(): string
    {
        return 'removeComments';
    }

    public function apply(string $value): string
    {
        $value = (string) preg_replace('#/\*.*?\*/#s', '', $value);
        $value = (string) preg_replace('/--[^\r\n]*/', '', $value);
        return (string) preg_replace('/#[^\r\n]*/', '', $value);
    }
}

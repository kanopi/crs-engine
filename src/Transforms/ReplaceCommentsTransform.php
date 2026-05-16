<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * Replaces SQL/C-style comments with a single space so SQLi rules can
 * still see token boundaries after evasion attempts.
 */
final class ReplaceCommentsTransform implements TransformInterface
{
    public function name(): string
    {
        return 'replaceComments';
    }

    public function apply(string $value): string
    {
        return (string) preg_replace('#/\*.*?\*/#s', ' ', $value);
    }
}

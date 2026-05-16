<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * Normalises command-line input the way ModSecurity does so RCE rules
 * match through common evasion attempts:
 *  - delete backslashes, single quotes, double quotes, carets
 *  - delete leading whitespace around commas and semicolons
 *  - collapse repeated whitespace to a single space
 *  - lowercase the result
 */
final class CmdLineTransform implements TransformInterface
{
    public function name(): string
    {
        return 'cmdLine';
    }

    public function apply(string $value): string
    {
        $value = str_replace(['\\', "'", '"', '^'], '', $value);
        $value = (string) preg_replace('/\s+([,;])/', '$1', $value);
        $value = (string) preg_replace('/([,;])\s+/', '$1', $value);
        $value = (string) preg_replace('/\s+/', ' ', $value);
        $value = (string) preg_replace('#/+#', '/', $value);
        return strtolower($value);
    }
}

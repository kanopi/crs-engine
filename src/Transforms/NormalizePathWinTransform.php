<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * `t:normalizePathWin` — convert Windows separators to forward slashes, then
 * normalise as normalizePath does.
 *
 * CRS pairs this with normalizePath on the LFI rules so `..\..\windows\win.ini`
 * is seen the same way as its POSIX spelling.
 */
final class NormalizePathWinTransform extends NormalisePathTransform
{
    public function name(): string
    {
        return 'normalizePathWin';
    }

    public function apply(string $value): string
    {
        return parent::apply(str_replace('\\', '/', $value));
    }
}

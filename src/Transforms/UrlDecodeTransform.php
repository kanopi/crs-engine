<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class UrlDecodeTransform implements TransformInterface
{
    public function name(): string
    {
        return 'urlDecode';
    }

    public function apply(string $value): string
    {
        return rawurldecode($value);
    }
}

<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class Base64DecodeTransform implements TransformInterface
{
    public function name(): string
    {
        return 'base64Decode';
    }

    public function apply(string $value): string
    {
        $decoded = base64_decode($value, true);
        return $decoded === false ? $value : $decoded;
    }
}

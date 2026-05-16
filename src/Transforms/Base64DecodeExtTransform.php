<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * Lenient base64 decoder that tolerates non-base64 characters by stripping
 * them first, matching ModSecurity's t:base64DecodeExt.
 */
final class Base64DecodeExtTransform implements TransformInterface
{
    public function name(): string
    {
        return 'base64DecodeExt';
    }

    public function apply(string $value): string
    {
        $cleaned = (string) preg_replace('#[^A-Za-z0-9+/=]#', '', $value);
        $decoded = base64_decode($cleaned, true);
        return $decoded === false ? $value : $decoded;
    }
}

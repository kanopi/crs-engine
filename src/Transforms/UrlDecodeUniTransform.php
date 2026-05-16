<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * URL-decoding that also handles IIS-style %uXXXX Unicode escapes,
 * matching ModSecurity's t:urlDecodeUni behavior.
 */
final class UrlDecodeUniTransform implements TransformInterface
{
    public function name(): string
    {
        return 'urlDecodeUni';
    }

    public function apply(string $value): string
    {
        $decoded = preg_replace_callback(
            '/%u([0-9a-fA-F]{4})/',
            static function (array $m): string {
                $code = hexdec($m[1]);
                return mb_convert_encoding(
                    pack('n', $code),
                    'UTF-8',
                    'UTF-16BE'
                );
            },
            $value
        );

        return rawurldecode($decoded ?? $value);
    }
}

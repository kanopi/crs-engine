<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * Converts each multi-byte UTF-8 character into a \uXXXX escape sequence,
 * matching ModSecurity's t:utf8toUnicode.
 */
final class Utf8ToUnicodeTransform implements TransformInterface
{
    public function name(): string
    {
        return 'utf8toUnicode';
    }

    public function apply(string $value): string
    {
        // Almost every value a WAF sees is plain ASCII and comes back
        // unchanged. Checking for a high byte first avoids the multibyte walk
        // entirely — this transform showed up at ~6% of request time because
        // it was paying for mb_* on ASCII.
        if (!preg_match('/[\x80-\xff]/', $value)) {
            return $value;
        }

        // One pass over the multibyte sequences rather than mb_substr() per
        // character, which rescans from the start of the string each time.
        return (string) preg_replace_callback(
            '/[\xc0-\xff][\x80-\xbf]*/',
            static function (array $m): string {
                $codePoints = unpack('N*', mb_convert_encoding($m[0], 'UTF-32BE', 'UTF-8'));
                if ($codePoints === false) {
                    return $m[0];
                }

                $out = '';
                foreach ($codePoints as $codePoint) {
                    $out .= sprintf('%%u%04x', $codePoint);
                }

                return $out;
            },
            $value,
        );
    }
}

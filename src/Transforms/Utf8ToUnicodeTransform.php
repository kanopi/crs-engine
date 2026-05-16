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
        $result = '';
        $len    = mb_strlen($value, 'UTF-8');
        for ($i = 0; $i < $len; $i++) {
            $char = mb_substr($value, $i, 1, 'UTF-8');
            if (strlen($char) === 1) {
                $result .= $char;
                continue;
            }

            $codePoints = unpack('N*', mb_convert_encoding($char, 'UTF-32BE', 'UTF-8'));
            if ($codePoints === false) {
                $result .= $char;
                continue;
            }

            foreach ($codePoints as $codePoint) {
                $result .= sprintf('%%u%04x', $codePoint);
            }
        }

        return $result;
    }
}

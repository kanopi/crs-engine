<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * `t:escapeSeqDecode` — decode C-style escape sequences.
 *
 * Seven occurrences in the RCE rules, where a shell payload can be written with
 * escapes to keep the recognisable words apart.
 *
 * Handles the single-character escapes, `\xHH`, and octal `\OOO` of up to three
 * digits. A backslash before anything else is left alone, which is where this
 * differs from jsDecode: an unrecognised escape here keeps its backslash.
 */
final class EscapeSeqDecodeTransform implements TransformInterface
{
    private const SINGLE = [
        'a' => "\x07", 'b' => "\x08", 'f' => "\x0c", 'n' => "\x0a",
        'r' => "\x0d", 't' => "\x09", 'v' => "\x0b",
        '\\' => '\\', '?' => '?', "'" => "'", '"' => '"',
    ];

    public function name(): string
    {
        return 'escapeSeqDecode';
    }

    public function apply(string $value): string
    {
        if (!str_contains($value, '\\')) {
            return $value;
        }

        $out    = '';
        $length = strlen($value);

        for ($i = 0; $i < $length; $i++) {
            if ($value[$i] !== '\\' || $i + 1 >= $length) {
                $out .= $value[$i];
                continue;
            }

            $next = $value[$i + 1];

            if ($next === 'x' && $i + 3 < $length && ctype_xdigit(substr($value, $i + 2, 2))) {
                $out .= chr((int) hexdec(substr($value, $i + 2, 2)));
                $i += 3;
                continue;
            }

            $octal = '';
            $j     = $i + 1;
            while ($j < $length && strlen($octal) < 3 && $value[$j] >= '0' && $value[$j] <= '7') {
                $octal .= $value[$j];
                $j++;
            }

            if ($octal !== '') {
                $out .= chr((int) octdec($octal) & 0xFF);
                $i = $j - 1;
                continue;
            }

            if (isset(self::SINGLE[$next])) {
                $out .= self::SINGLE[$next];
                $i++;
                continue;
            }

            // Unrecognised: both characters survive, unlike jsDecode.
            $out .= $value[$i];
        }

        return $out;
    }
}

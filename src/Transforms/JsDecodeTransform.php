<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * `t:jsDecode` — decode JavaScript escape sequences.
 *
 * The most-used transform this engine was missing: 35 occurrences across the
 * XSS, generic-attack and Java rule files, every one of them an anti-evasion
 * step. Without it those rules saw `<script>` rather than
 * `<script>`.
 *
 * Follows ModSecurity's js_decode_nonstrict_inplace_ex: single-character
 * escapes, `\xHH`, and `\uHHHH`. Full-width forms (U+FF01–U+FF5E) are folded to
 * their ASCII equivalents, which is how the fullwidth-character bypass is
 * defeated; other `\u` values are reduced to their low byte, as upstream does.
 * A backslash before anything else yields that character, so `\q` becomes `q`.
 */
final class JsDecodeTransform implements TransformInterface
{
    private const SINGLE = [
        'a' => "\x07", 'b' => "\x08", 'f' => "\x0c", 'n' => "\x0a",
        'r' => "\x0d", 't' => "\x09", 'v' => "\x0b",
        '\\' => '\\', '?' => '?', "'" => "'", '"' => '"',
    ];

    public function name(): string
    {
        return 'jsDecode';
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

            if ($next === 'u' && $i + 5 < $length && ctype_xdigit(substr($value, $i + 2, 4))) {
                $out .= $this->fromCodePoint((int) hexdec(substr($value, $i + 2, 4)));
                $i += 5;
                continue;
            }

            if ($next === 'x' && $i + 3 < $length && ctype_xdigit(substr($value, $i + 2, 2))) {
                $out .= chr((int) hexdec(substr($value, $i + 2, 2)));
                $i += 3;
                continue;
            }

            if (isset(self::SINGLE[$next])) {
                $out .= self::SINGLE[$next];
                $i++;
                continue;
            }

            // Not an escape this engine knows: the backslash goes, the
            // character stays, which is what upstream does.
            $out .= $next;
            $i++;
        }

        return $out;
    }

    private function fromCodePoint(int $codePoint): string
    {
        // Full-width Latin folds onto ASCII. `＜script＞` is the
        // classic form of this bypass.
        if ($codePoint >= 0xFF01 && $codePoint <= 0xFF5E) {
            return chr($codePoint - 0xFEE0);
        }

        return chr($codePoint & 0xFF);
    }
}

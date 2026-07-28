<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * `t:cssDecode` — decode CSS escape sequences.
 *
 * 21 occurrences in the XSS rules. CSS lets any character be written as a
 * backslash followed by up to six hex digits, so `\65 xpression` and
 * `\000065xpression` both spell `expression`; without decoding, the rules
 * looking for `expression(` never see it.
 *
 * A single whitespace character after the hex run is part of the escape and is
 * consumed. A backslash before a newline is a line continuation and both go.
 * A backslash before any other character yields that character.
 */
final class CssDecodeTransform implements TransformInterface
{
    public function name(): string
    {
        return 'cssDecode';
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

            $hex = '';
            $j   = $i + 1;
            while ($j < $length && strlen($hex) < 6 && ctype_xdigit($value[$j])) {
                $hex .= $value[$j];
                $j++;
            }

            if ($hex !== '') {
                $out .= chr((int) hexdec($hex) & 0xFF);

                // One trailing whitespace terminates the escape and is eaten.
                if ($j < $length && (in_array($value[$j], [' ', "\t", "\n", "\r", "\f"], true))) {
                    $j++;
                }

                $i = $j - 1;
                continue;
            }

            // Line continuation: backslash-newline disappears entirely.
            if ($value[$i + 1] === "\n" || $value[$i + 1] === "\r") {
                $i++;
                continue;
            }

            $out .= $value[$i + 1];
            $i++;
        }

        return $out;
    }
}

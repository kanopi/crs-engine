<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

/**
 * @validateUrlEncoding — flags invalid percent-encoding (truncated %X or
 * non-hex chars after %). CRS uses this in protocol-enforcement.
 */
final class ValidateUrlEncodingOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'validateUrlEncoding';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        $len = strlen($value);
        for ($i = 0; $i < $len; $i++) {
            if ($value[$i] !== '%') {
                continue;
            }

            if ($i + 2 >= $len) {
                return OperatorMatch::hit('truncated %-encoding');
            }

            $h1 = $value[$i + 1];
            $h2 = $value[$i + 2];
            if (!ctype_xdigit($h1) || !ctype_xdigit($h2)) {
                return OperatorMatch::hit(sprintf('invalid %%-encoding: %%%s%s', $h1, $h2));
            }

            $i += 2;
        }

        return OperatorMatch::miss();
    }
}

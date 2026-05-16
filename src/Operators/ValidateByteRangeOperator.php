<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

/**
 * @validateByteRange — match when $value contains a byte outside the
 * allowed comma-separated list of bytes/ranges (e.g. "32-126,9,10,13").
 * Used in CRS for protocol-enforcement (e.g. URI must be printable ASCII).
 */
final class ValidateByteRangeOperator implements OperatorInterface
{
    /** @var array<string, array<int, bool>> */
    private static array $allowedCache = [];

    public function name(): string
    {
        return 'validateByteRange';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        $allowed = self::$allowedCache[$argument] ?? null;
        if ($allowed === null) {
            $allowed = array_fill(0, 256, false);
            foreach (explode(',', $argument) as $part) {
                $part = trim($part);
                if (str_contains($part, '-')) {
                    [$lo, $hi] = array_map(intval(...), explode('-', $part, 2));
                    for ($i = $lo; $i <= $hi; $i++) {
                        if ($i >= 0 && $i <= 255) {
                            $allowed[$i] = true;
                        }
                    }
                } elseif ($part !== '') {
                    $b = (int) $part;
                    if ($b >= 0 && $b <= 255) {
                        $allowed[$b] = true;
                    }
                }
            }

            self::$allowedCache[$argument] = $allowed;
        }

        $len = strlen($value);
        for ($i = 0; $i < $len; $i++) {
            if (!$allowed[ord($value[$i])]) {
                return OperatorMatch::hit(sprintf('byte 0x%02x at offset %d', ord($value[$i]), $i));
            }
        }

        return OperatorMatch::miss();
    }
}

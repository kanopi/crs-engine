<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class ValidateUtf8EncodingOperator implements OperatorInterface
{
    public function name(): string
    {
        return 'validateUtf8Encoding';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        if (mb_check_encoding($value, 'UTF-8')) {
            return OperatorMatch::miss();
        }

        return OperatorMatch::hit('invalid UTF-8 sequence');
    }
}

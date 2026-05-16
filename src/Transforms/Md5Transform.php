<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class Md5Transform implements TransformInterface
{
    public function name(): string
    {
        return 'md5';
    }

    public function apply(string $value): string
    {
        return md5($value);
    }
}

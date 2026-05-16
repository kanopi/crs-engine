<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class Sha1Transform implements TransformInterface
{
    public function name(): string
    {
        return 'sha1';
    }

    public function apply(string $value): string
    {
        return sha1($value);
    }
}

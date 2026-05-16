<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

interface TransformInterface
{
    public function name(): string;

    public function apply(string $value): string;
}

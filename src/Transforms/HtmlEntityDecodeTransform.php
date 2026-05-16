<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

final class HtmlEntityDecodeTransform implements TransformInterface
{
    public function name(): string
    {
        return 'htmlEntityDecode';
    }

    public function apply(string $value): string
    {
        return html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}

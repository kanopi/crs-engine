<?php

declare(strict_types=1);

namespace Kanopi\Crs\Runtime;

use Kanopi\Crs\Transforms\TransformRegistry;

final class TransformPipeline
{
    public function __construct(private readonly TransformRegistry $transformRegistry)
    {
    }

    /**
     * Apply a list of transforms left-to-right. "none" resets the chain.
     *
     * @param array<int, string> $transforms
     */
    public function apply(array $transforms, string $value): string
    {
        foreach ($this->each($transforms, $value) as $candidate) {
            $value = $candidate;
        }

        return $value;
    }

    /**
     * Yield the value before any transform plus after each transform step.
     * Used by the multiMatch evaluator so a rule can match a value mid-pipeline
     * (e.g. after t:urlDecode but before t:htmlEntityDecode).
     *
     * @param array<int, string> $transforms
     * @return \Generator<int, string>
     */
    public function each(array $transforms, string $value): \Generator
    {
        $effective = [];
        foreach ($transforms as $name) {
            if (strtolower($name) === 'none') {
                $effective = [];
                continue;
            }

            $effective[] = $name;
        }

        yield $value;

        foreach ($effective as $name) {
            if (!$this->transformRegistry->has($name)) {
                $this->transformRegistry->recordUnknown($name);
                continue;
            }

            $value = $this->transformRegistry->get($name)->apply($value);
            yield $value;
        }
    }
}

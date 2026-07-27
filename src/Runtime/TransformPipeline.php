<?php

declare(strict_types=1);

namespace Kanopi\Crs\Runtime;

use Kanopi\Crs\Transforms\TransformInterface;
use Kanopi\Crs\Transforms\TransformRegistry;

final class TransformPipeline
{
    /**
     * Resolved transform objects per transform list.
     *
     * The `none` filtering and the registry has()/get() pair used to run for
     * every transform, of every rule, against every resolved value — the two
     * lookups alone accounted for ~8,000 calls on a ten-argument request. The
     * list attached to a rule never changes, so resolve it once.
     *
     * @var array<string, array<int, TransformInterface>>
     */
    private array $resolved = [];

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
        return $this->applyResolved($this->resolve($transforms), $value);
    }

    /**
     * As apply(), for a list already put through resolve().
     *
     * Deliberately not written in terms of each(): this is the common path,
     * and driving a generator purely to take its last value cost more than the
     * transforms themselves.
     *
     * @param array<int, TransformInterface> $transforms
     */
    public function applyResolved(array $transforms, string $value): string
    {
        foreach ($transforms as $transform) {
            $value = $transform->apply($value);
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
        yield from $this->eachResolved($this->resolve($transforms), $value);
    }

    /**
     * As each(), for a list already put through resolve().
     *
     * @param array<int, TransformInterface> $transforms
     * @return \Generator<int, string>
     */
    public function eachResolved(array $transforms, string $value): \Generator
    {
        yield $value;

        foreach ($transforms as $transform) {
            $value = $transform->apply($value);
            yield $value;
        }
    }

    /**
     * Turn a rule's transform names into the objects that implement them.
     * Callers on the hot path should do this once per rule rather than once
     * per resolved value — building the cache key is itself measurable.
     *
     * @param array<int, string> $transforms
     * @return array<int, TransformInterface>
     */
    public function resolve(array $transforms): array
    {
        if ($transforms === []) {
            return [];
        }

        $key = implode('|', $transforms);
        if (isset($this->resolved[$key])) {
            return $this->resolved[$key];
        }

        $names = [];
        foreach ($transforms as $name) {
            // `t:none` discards everything declared before it.
            if (strcasecmp($name, 'none') === 0) {
                $names = [];
                continue;
            }

            $names[] = $name;
        }

        $out = [];
        foreach ($names as $name) {
            if (!$this->transformRegistry->has($name)) {
                $this->transformRegistry->recordUnknown($name);
                continue;
            }

            $out[] = $this->transformRegistry->get($name);
        }

        return $this->resolved[$key] = $out;
    }
}

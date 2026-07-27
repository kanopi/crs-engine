<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Variables;

use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Runtime\TxStore;
use Kanopi\Crs\Variables\ResolvedValue;
use Kanopi\Crs\Variables\VariableResolver;
use PHPUnit\Framework\TestCase;

/**
 * ARGS is the concatenation of the query and body bags, not a merge. A
 * name-keyed union drops one of two same-named parameters, which let a payload
 * hide in POST behind a benign query parameter of the same name.
 */
final class ArgsCollisionTest extends TestCase
{
    public function testArgsYieldsBothValuesWhenNamesCollide(): void
    {
        $values = $this->resolve('ARGS', ['id' => 'harmless'], ['id' => "' OR 1=1"]);

        $this->assertCount(2, $values, 'A name present in both bags is two values, not one.');
        $this->assertSame(['harmless', "' OR 1=1"], $this->values($values));
    }

    public function testArgsNamesYieldsBothOccurrencesWhenNamesCollide(): void
    {
        $values = $this->resolve('ARGS_NAMES', ['id' => 'harmless'], ['id' => 'payload']);

        $this->assertSame(['id', 'id'], $this->values($values));
    }

    public function testQueryArgsAreOrderedBeforePostArgs(): void
    {
        $this->assertSame(['1', '2'], $this->values($this->resolve('ARGS', ['a' => '1'], ['b' => '2'])));
    }

    public function testArgsStillResolvesEachBagAlone(): void
    {
        $this->assertSame(['get'], $this->values($this->resolve('ARGS', ['only' => 'get'], [])));
        $this->assertSame(['post'], $this->values($this->resolve('ARGS', [], ['only' => 'post'])));
        $this->assertSame([], $this->resolve('ARGS', [], []));
    }

    public function testSelectorMatchesTheSameNameInBothBags(): void
    {
        $values = $this->resolve('ARGS', ['id' => 'get'], ['id' => 'post'], selector: 'id');

        $this->assertSame(['get', 'post'], $this->values($values));
    }

    public function testNegatedTargetExcludesTheNameFromBothBags(): void
    {
        $values = (new VariableResolver(new TxStore()))->resolve([
            ['collection' => 'ARGS'],
            ['collection' => 'ARGS', 'selector' => 'id', 'negated' => true],
        ], $this->req(['id' => 'get', 'keep' => 'q'], ['id' => 'post']));

        $this->assertSame(['q'], $this->values($values));
    }

    public function testCountFormSeesBothOccurrences(): void
    {
        $values = (new VariableResolver(new TxStore()))->resolve([
            ['collection' => 'ARGS', 'count' => true],
        ], $this->req(['id' => 'get'], ['id' => 'post']));

        $this->assertSame('2', $values[0]->value, 'A duplicated name counts twice for &ARGS.');
    }

    public function testArgsGetAndArgsPostStayScopedToTheirOwnBag(): void
    {
        $this->assertSame(['get'], $this->values($this->resolve('ARGS_GET', ['id' => 'get'], ['id' => 'post'])));
        $this->assertSame(['post'], $this->values($this->resolve('ARGS_POST', ['id' => 'get'], ['id' => 'post'])));
    }

    /**
     * @param array<int, ResolvedValue> $resolved
     * @return array<int, string>
     */
    private function values(array $resolved): array
    {
        return array_map(static fn (ResolvedValue $resolvedValue): string => $resolvedValue->value, $resolved);
    }

    /**
     * @param array<string, string|array<int|string, mixed>> $get
     * @param array<string, string|array<int|string, mixed>> $post
     * @return array<int, ResolvedValue>
     */
    private function resolve(string $collection, array $get, array $post, ?string $selector = null): array
    {
        $target = ['collection' => $collection];
        if ($selector !== null) {
            $target['selector'] = $selector;
        }

        return (new VariableResolver(new TxStore()))->resolve([$target], $this->req($get, $post));
    }

    /**
     * @param array<string, string|array<int|string, mixed>> $get
     * @param array<string, string|array<int|string, mixed>> $post
     */
    private function req(array $get, array $post): RequestData
    {
        return new RequestData(
            method: 'POST',
            uri: '/',
            rawUri: '/',
            queryString: http_build_query($get),
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            queryArgs: $get,
            postArgs: $post,
            body: http_build_query($post),
        );
    }
}

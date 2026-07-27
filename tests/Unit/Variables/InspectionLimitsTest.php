<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Variables;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Request\ResponseData;
use Kanopi\Crs\Runtime\TxStore;
use Kanopi\Crs\Variables\ResolvedValue;
use Kanopi\Crs\Variables\VariableResolver;
use PHPUnit\Framework\TestCase;

/**
 * Caps on how much of a request goes through the ruleset. Cost is the product
 * of rules and bytes, so both the number of arguments and their total size need
 * a ceiling — one 2.5 MB argument costs about what ten thousand small ones do.
 */
final class InspectionLimitsTest extends TestCase
{
    /**
     * @param array<string, string> $args
     */
    private function req(array $args = [], string $body = ''): RequestData
    {
        return new RequestData(
            method: 'POST',
            uri: '/',
            rawUri: '/',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            postArgs: $args,
            body: $body,
        );
    }

    /**
     * @return array<string, string>
     */
    private function manyArgs(int $count, int $valueLength = 4): array
    {
        $args = [];
        for ($i = 0; $i < $count; $i++) {
            $args['p' . $i] = str_repeat('a', $valueLength);
        }

        return $args;
    }

    public function testArgCountIsCapped(): void
    {
        $variableResolver = new VariableResolver(new TxStore(), null, 10);
        $values = $variableResolver->resolve([['collection' => 'ARGS']], $this->req($this->manyArgs(100)));

        $this->assertCount(10, $values);
        $this->assertSame(
            [['what' => 'args', 'inspected' => 10, 'total' => 100]],
            $variableResolver->truncations()
        );
    }

    public function testArgCountUnderTheCapIsNotTruncated(): void
    {
        $variableResolver = new VariableResolver(new TxStore(), null, 10);
        $values = $variableResolver->resolve([['collection' => 'ARGS']], $this->req($this->manyArgs(10)));

        $this->assertCount(10, $values);
        $this->assertSame([], $variableResolver->truncations());
    }

    /**
     * The cap must not reach counting. CRS 920380 blocks on `&ARGS` exceeding
     * tx.max_num_args, so a truncated count would silence the rule that flags
     * an over-large request — turning a flagged truncation into a silent one.
     */
    public function testCountingIsNotCapped(): void
    {
        $variableResolver = new VariableResolver(new TxStore(), null, 10);
        $values = $variableResolver->resolve(
            [['collection' => 'ARGS', 'count' => true]],
            $this->req($this->manyArgs(100))
        );

        $this->assertSame('100', $values[0]->value);
    }

    public function testUnlimitedArgsInspectsEverything(): void
    {
        $variableResolver = new VariableResolver(new TxStore(), null, CrsConfig::UNLIMITED);
        $values = $variableResolver->resolve([['collection' => 'ARGS']], $this->req($this->manyArgs(500)));

        $this->assertCount(500, $values);
        $this->assertSame([], $variableResolver->truncations());
    }

    public function testTotalArgBytesAreCapped(): void
    {
        $variableResolver = new VariableResolver(new TxStore(), null, CrsConfig::UNLIMITED, CrsConfig::UNLIMITED, 100);
        $values = $variableResolver->resolve(
            [['collection' => 'ARGS']],
            $this->req(['a' => str_repeat('x', 60), 'b' => str_repeat('y', 60), 'c' => str_repeat('z', 60)])
        );

        $this->assertSame(100, array_sum(array_map(
            static fn (ResolvedValue $resolvedValue): int => strlen($resolvedValue->value),
            $values
        )), 'The budget should be spent exactly, not overshot.');
        $this->assertSame(
            [['what' => 'arg_bytes', 'inspected' => 100, 'total' => 180]],
            $variableResolver->truncations()
        );
    }

    /**
     * A payload at the front of an oversized argument is still worth catching,
     * so the value that crosses the budget is truncated rather than dropped.
     */
    public function testTheValueCrossingTheBudgetKeepsItsPrefix(): void
    {
        $variableResolver = new VariableResolver(new TxStore(), null, CrsConfig::UNLIMITED, CrsConfig::UNLIMITED, 20);
        $values = $variableResolver->resolve(
            [['collection' => 'ARGS']],
            $this->req(['q' => 'PAYLOAD' . str_repeat('.', 500)])
        );

        $this->assertCount(1, $values);
        $this->assertSame(20, strlen($values[0]->value));
        $this->assertStringStartsWith('PAYLOAD', $values[0]->value);
    }

    public function testASingleHugeArgumentIsBoundedByBytesNotCount(): void
    {
        // One argument is under any count cap, so only the byte cap can bound it.
        $variableResolver = new VariableResolver(new TxStore(), null, 255, CrsConfig::UNLIMITED, 1000);
        $values = $variableResolver->resolve(
            [['collection' => 'ARGS']],
            $this->req(['q' => str_repeat('a', 500_000)])
        );

        $this->assertSame(1000, strlen($values[0]->value));
        $this->assertSame('arg_bytes', $variableResolver->truncations()[0]['what']);
    }

    public function testNonArgCollectionsAreNotSubjectToTheArgCaps(): void
    {
        $variableResolver = new VariableResolver(new TxStore(), null, 1, CrsConfig::UNLIMITED, 1);
        $requestData = new RequestData(
            method: 'GET',
            uri: '/',
            rawUri: '/',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            headers: ['a' => 'xxxxxxxxxx', 'b' => 'yyyyyyyyyy', 'c' => 'zzzzzzzzzz'],
        );

        $values = $variableResolver->resolve([['collection' => 'REQUEST_HEADERS']], $requestData);

        $this->assertCount(3, $values, 'Header caps are a separate concern; these limits are argument-scoped.');
        $this->assertSame([], $variableResolver->truncations());
    }

    public function testRequestBodyIsCapped(): void
    {
        $variableResolver = new VariableResolver(new TxStore(), null, CrsConfig::UNLIMITED, 50);
        $values = $variableResolver->resolve(
            [['collection' => 'REQUEST_BODY']],
            $this->req([], str_repeat('b', 500))
        );

        $this->assertSame(50, strlen($values[0]->value));
        $this->assertSame(
            [['what' => 'request_body', 'inspected' => 50, 'total' => 500]],
            $variableResolver->truncations()
        );
    }

    public function testResponseBodyIsCapped(): void
    {
        $responseData = new ResponseData(status: 200, body: str_repeat('c', 500));
        $variableResolver = new VariableResolver(
            new TxStore(),
            $responseData,
            CrsConfig::UNLIMITED,
            CrsConfig::UNLIMITED,
            CrsConfig::UNLIMITED,
            maxResponseBodyBytes: 50,
        );

        $values = $variableResolver->resolve([['collection' => 'RESPONSE_BODY']], $this->req());

        $this->assertSame(50, strlen($values[0]->value));
        $this->assertSame('response_body', $variableResolver->truncations()[0]['what']);
    }

    /**
     * A prefix of a document is not a document: DOM would reject it and report
     * nothing, with no record of why. Refusing up front keeps the reason.
     */
    public function testOversizedXmlBodyIsRefusedRatherThanParsedTruncated(): void
    {
        $xml = '<?xml version="1.0"?><r><v>' . str_repeat('d', 500) . '</v></r>';
        $variableResolver = new VariableResolver(new TxStore(), null, CrsConfig::UNLIMITED, 50);

        $values = $variableResolver->resolve([['collection' => 'XML', 'selector' => '/*']], $this->req([], $xml));

        $this->assertSame([], $values);
        $this->assertSame('xml_body', $variableResolver->truncations()[0]['what']);
    }

    public function testXmlUnderTheCapStillParses(): void
    {
        $xml = '<?xml version="1.0"?><r><v>hello</v></r>';
        $variableResolver = new VariableResolver(new TxStore(), null, CrsConfig::UNLIMITED, 10_000);

        $values = $variableResolver->resolve([['collection' => 'XML', 'selector' => '//v']], $this->req([], $xml));

        $this->assertNotSame([], $values);
        $this->assertSame('hello', $values[0]->value);
        $this->assertSame([], $variableResolver->truncations());
    }

    public function testTruncationsAreReportedOncePerKindNotPerRule(): void
    {
        $variableResolver = new VariableResolver(new TxStore(), null, 10);
        $req = $this->req($this->manyArgs(100));

        // Stands in for many rules each resolving ARGS.
        for ($i = 0; $i < 5; $i++) {
            $variableResolver->resolve([['collection' => 'ARGS']], $req);
        }

        $this->assertCount(1, $variableResolver->truncations());
    }

    public function testAResolverWithNoLimitsBehavesAsBefore(): void
    {
        $variableResolver = new VariableResolver(new TxStore());
        $values = $variableResolver->resolve([['collection' => 'ARGS']], $this->req($this->manyArgs(1000)));

        $this->assertCount(1000, $values);
        $this->assertSame([], $variableResolver->truncations());
    }
}

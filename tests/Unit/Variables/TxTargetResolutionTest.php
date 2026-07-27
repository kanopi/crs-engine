<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Variables;

use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Runtime\TxStore;
use Kanopi\Crs\Variables\VariableResolver;
use PHPUnit\Framework\TestCase;

/**
 * Regression cover for the setvar/TX naming mismatch.
 *
 * CRS rules write TX variables prefixed (`setvar:'tx.foo=1'`) and read them
 * back unprefixed (`SecRule TX:FOO`). Before the fix, the read side did a bare
 * lookup and missed every variable the ruleset had written, leaving 242 of 583
 * rules permanently unable to fire.
 */
final class TxTargetResolutionTest extends TestCase
{
    private VariableResolver $resolver;

    private TxStore $txStore;

    private RequestData $requestData;

    protected function setUp(): void
    {
        $this->txStore = new TxStore();
        $this->resolver = new VariableResolver($this->txStore);
        $this->requestData = new RequestData(
            method: 'GET',
            uri: '/',
            rawUri: '/',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
        );
    }

    /**
     * @return array<int, string>
     */
    private function resolveTx(string $selector): array
    {
        $values = $this->resolver->resolve(
            [['collection' => 'TX', 'selector' => $selector]],
            $this->requestData,
        );

        return array_map(static fn ($v): string => $v->value, $values);
    }

    public function testPrefixedSetvarIsReadableByUnprefixedTarget(): void
    {
        // How setvar writes it.
        $this->txStore->set('tx.anomaly_score', '42');

        // How the rule addresses it.
        $this->assertSame(['42'], $this->resolveTx('ANOMALY_SCORE'));
    }

    public function testLookupIsCaseInsensitive(): void
    {
        $this->txStore->set('tx.blocking_inbound_anomaly_score', '7');

        $this->assertSame(['7'], $this->resolveTx('BLOCKING_INBOUND_ANOMALY_SCORE'));
        $this->assertSame(['7'], $this->resolveTx('blocking_inbound_anomaly_score'));
    }

    public function testExplicitlyPrefixedSelectorStillResolves(): void
    {
        $this->txStore->set('tx.foo', 'bar');

        $this->assertSame(['bar'], $this->resolveTx('tx.foo'));
    }

    public function testUnprefixedSetvarIsStillReadable(): void
    {
        // A rule may set a TX var without the prefix; the direct hit must win
        // before the fallback is consulted.
        $this->txStore->set('bare', 'value');

        $this->assertSame(['value'], $this->resolveTx('bare'));
    }

    public function testDirectHitTakesPrecedenceOverPrefixedFallback(): void
    {
        $this->txStore->set('score', 'direct');
        $this->txStore->set('tx.score', 'prefixed');

        $this->assertSame(['direct'], $this->resolveTx('score'));
    }

    public function testUnsetVariableResolvesToNothing(): void
    {
        $this->assertSame([], $this->resolveTx('NEVER_SET'));
    }

    /**
     * A dotted selector is already namespaced, so it must not acquire a second
     * `tx.` prefix and accidentally hit an unrelated key.
     */
    public function testDottedSelectorIsNotDoublePrefixed(): void
    {
        $this->txStore->set('tx.tx.weird', 'wrong');

        $this->assertSame([], $this->resolveTx('tx.weird'));
    }
}

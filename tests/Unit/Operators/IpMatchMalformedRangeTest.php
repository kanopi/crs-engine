<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Operators;

use Kanopi\Crs\Operators\IpMatchOperator;
use PHPUnit\Framework\TestCase;

/**
 * A typo in a CIDR prefix should degrade the rule carrying it, not the request.
 *
 * Unclamped, /33 on an IPv4 address indexed past the end of the packed address
 * and raised an uncaught Error out of the middle of evaluation, and a negative
 * prefix produced a zero mask that matched every address.
 */
final class IpMatchMalformedRangeTest extends TestCase
{
    private IpMatchOperator $ipMatchOperator;

    protected function setUp(): void
    {
        $this->ipMatchOperator = new IpMatchOperator();
    }

    /**
     * @return \Iterator<string, array{string}>
     */
    public static function malformedRangeProvider(): \Iterator
    {
        yield 'ipv4 prefix one past the end' => ['192.0.2.0/33'];
        yield 'ipv4 prefix far too large' => ['192.0.2.0/999'];
        yield 'ipv6 prefix too large' => ['2001:db8::/129'];
        yield 'negative prefix' => ['192.0.2.0/-1'];
        yield 'non-numeric prefix' => ['192.0.2.0/abc'];
        yield 'empty prefix' => ['192.0.2.0/'];
        yield 'bare slash' => ['/24'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('malformedRangeProvider')]
    public function testMalformedRangeDoesNotThrow(string $range): void
    {
        $this->ipMatchOperator->evaluate($range, '198.51.100.7');
        $this->ipMatchOperator->evaluate($range, '2001:db8::1');

        $this->expectNotToPerformAssertions();
    }

    /**
     * The dangerous half. A zero prefix masks nothing, so anything that lands
     * on 0 matches every address in the family — a typo would silently turn a
     * targeted range into a universal one. Casting sends `/-1` and `/abc` both
     * to 0, so neither may be cast; they are dropped instead.
     *
     * @return \Iterator<string, array{string}>
     */
    public static function unparseablePrefixProvider(): \Iterator
    {
        yield 'negative prefix' => ['192.0.2.0/-1'];
        yield 'non-numeric prefix' => ['192.0.2.0/abc'];
        yield 'empty prefix' => ['192.0.2.0/'];
        yield 'float prefix' => ['192.0.2.0/24.5'];
        yield 'leading plus' => ['192.0.2.0/+24'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('unparseablePrefixProvider')]
    public function testUnparseablePrefixMatchesNothingRatherThanEverything(string $range): void
    {
        $this->assertFalse($this->ipMatchOperator->evaluate($range, '198.51.100.7')->matched);
        $this->assertFalse($this->ipMatchOperator->evaluate($range, '10.0.0.1')->matched);
        $this->assertFalse(
            $this->ipMatchOperator->evaluate($range, '192.0.2.5')->matched,
            'Even an address inside the intended network: the range is unusable, not widened.'
        );
    }

    /**
     * An explicit /0 is a real range and still means what it says. Only the
     * unparseable prefixes are dropped.
     */
    public function testExplicitZeroPrefixStillMatchesEverything(): void
    {
        $this->assertTrue($this->ipMatchOperator->evaluate('192.0.2.0/0', '198.51.100.7')->matched);
    }

    public function testOversizedPrefixBehavesAsAFullLengthMatch(): void
    {
        $this->assertTrue($this->ipMatchOperator->evaluate('192.0.2.10/33', '192.0.2.10')->matched);
        $this->assertFalse($this->ipMatchOperator->evaluate('192.0.2.10/33', '192.0.2.11')->matched);
    }

    public function testOversizedIpv6PrefixBehavesAsAFullLengthMatch(): void
    {
        $this->assertTrue($this->ipMatchOperator->evaluate('2001:db8::1/129', '2001:db8::1')->matched);
        $this->assertFalse($this->ipMatchOperator->evaluate('2001:db8::1/129', '2001:db8::2')->matched);
    }

    public function testAMalformedEntryDoesNotDisableTheValidOnesBesideIt(): void
    {
        $argument = '192.0.2.0/abc, 10.0.0.0/8';

        $this->assertTrue($this->ipMatchOperator->evaluate($argument, '10.5.5.5')->matched);
        $this->assertFalse($this->ipMatchOperator->evaluate($argument, '198.51.100.7')->matched);
    }

    public function testWellFormedRangesAreUnaffected(): void
    {
        $this->assertTrue($this->ipMatchOperator->evaluate('10.0.0.0/8', '10.5.5.5')->matched);
        $this->assertFalse($this->ipMatchOperator->evaluate('10.0.0.0/8', '11.0.0.0')->matched);
        $this->assertTrue($this->ipMatchOperator->evaluate('192.0.2.128/25', '192.0.2.200')->matched);
        $this->assertFalse($this->ipMatchOperator->evaluate('192.0.2.128/25', '192.0.2.100')->matched);
        $this->assertTrue($this->ipMatchOperator->evaluate('2001:db8::/32', '2001:db8:1::1')->matched);
        $this->assertFalse($this->ipMatchOperator->evaluate('2001:db8::/32', '2001:db9::1')->matched);
    }

    public function testMixedFamiliesDoNotCrossMatch(): void
    {
        $this->assertFalse($this->ipMatchOperator->evaluate('10.0.0.0/8', '2001:db8::1')->matched);
        $this->assertFalse($this->ipMatchOperator->evaluate('2001:db8::/32', '10.5.5.5')->matched);
    }

    public function testUnparseableValueIsAMiss(): void
    {
        $this->assertFalse($this->ipMatchOperator->evaluate('10.0.0.0/8', 'not-an-ip')->matched);
        $this->assertFalse($this->ipMatchOperator->evaluate('10.0.0.0/8', '')->matched);
    }
}

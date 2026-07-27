<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\CrsVerdict;
use Kanopi\Crs\Request\RequestData;
use PHPUnit\Framework\TestCase;

/**
 * Integration: rule 911100 uses `!@within %{tx.allowed_methods}`, so a method
 * that is merely a substring of the allow-list used to pass enforcement — `OST`
 * occurs inside POST. Pinned against the real bundled ruleset.
 */
final class MethodEnforcementTest extends TestCase
{
    private CrsEngine $crsEngine;

    protected function setUp(): void
    {
        $this->crsEngine = new CrsEngine(new CrsConfig(paranoia: 1));
    }

    /**
     * @return \Iterator<string, array{string}>
     */
    public static function allowedMethodProvider(): \Iterator
    {
        yield 'GET' => ['GET'];
        yield 'HEAD' => ['HEAD'];
        yield 'POST' => ['POST'];
        yield 'OPTIONS' => ['OPTIONS'];
    }

    /**
     * @return \Iterator<string, array{string}>
     */
    public static function disallowedMethodProvider(): \Iterator
    {
        yield 'PUT' => ['PUT'];
        yield 'DELETE' => ['DELETE'];
        yield 'TRACE' => ['TRACE'];
        yield 'PATCH' => ['PATCH'];
        // Substrings of the allow-list — the bypass this test exists for.
        yield 'OST (substring of POST)' => ['OST'];
        yield 'HEA (substring of HEAD)' => ['HEA'];
        yield 'PTIONS (substring of OPTIONS)' => ['PTIONS'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('allowedMethodProvider')]
    public function testAllowedMethodDoesNotTripEnforcement(string $method): void
    {
        $crsVerdict = $this->verdict($method);

        $this->assertNotContains(
            911100,
            array_column($crsVerdict->matchedRules, 'id'),
            $method . ' is on the allow-list and must not trip 911100.'
        );
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('disallowedMethodProvider')]
    public function testDisallowedMethodTripsEnforcement(string $method): void
    {
        $crsVerdict = $this->verdict($method);

        $this->assertContains(
            911100,
            array_column($crsVerdict->matchedRules, 'id'),
            $method . ' is not on the allow-list, so 911100 must fire.'
        );
        $this->assertTrue($crsVerdict->isBlocked(), $method . ' should block at the default threshold.');
    }

    private function verdict(string $method): CrsVerdict
    {
        return $this->crsEngine->evaluate(new RequestData(
            method: $method,
            uri: '/',
            rawUri: '/',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            headers: ['host' => 'example.test'],
        ));
    }
}

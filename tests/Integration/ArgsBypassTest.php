<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\CrsVerdict;
use Kanopi\Crs\Request\RequestData;
use PHPUnit\Framework\TestCase;

/**
 * Integration: a payload in a POST parameter must be detected regardless of
 * whether a query parameter of the same name is also present.
 *
 * Resolving ARGS from a name-keyed union of the two bags dropped the POST
 * value on collision, so adding `?id=harmless` alongside a payload in POST:id
 * suppressed every ARGS rule — the bulk of the ruleset. Runs against the real
 * bundled ruleset because the point is the blast radius, not one fixture rule.
 */
final class ArgsBypassTest extends TestCase
{
    private CrsEngine $crsEngine;

    protected function setUp(): void
    {
        $this->crsEngine = new CrsEngine(new CrsConfig(paranoia: 1));
    }

    /**
     * @return \Iterator<string, array{string}>
     */
    public static function payloadProvider(): \Iterator
    {
        yield 'sqli tautology' => ["' OR 1=1 -- "];
        yield 'union select' => ['1 UNION ALL SELECT 1,2,3,4 -- '];
        yield 'script tag xss' => ['<script>alert(1)</script>'];
        yield 'lfi traversal' => ['../../etc/passwd'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('payloadProvider')]
    public function testPayloadInPostIsDetectedWithoutACollidingQueryParam(string $payload): void
    {
        $crsVerdict = $this->verdict([], ['id' => $payload]);

        $this->assertTrue($crsVerdict->isBlocked(), 'Baseline: payload in POST alone should block.');
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('payloadProvider')]
    public function testPayloadInPostIsStillDetectedBehindABenignQueryParam(string $payload): void
    {
        $crsVerdict = $this->verdict(['id' => 'harmless'], ['id' => $payload]);

        $this->assertTrue(
            $crsVerdict->isBlocked(),
            'A benign query param of the same name must not hide a payload in POST.'
        );
        $this->assertGreaterThanOrEqual(
            $this->verdict([], ['id' => $payload])->totalScore,
            $crsVerdict->totalScore,
            'Shadowing the name must not reduce the anomaly score.'
        );
    }

    public function testShadowingDoesNotSuppressMatchedRules(): void
    {
        $payload    = "' OR 1=1 -- ";
        $crsVerdict = $this->verdict(['id' => 'harmless'], ['id' => $payload]);

        $this->assertNotEmpty($crsVerdict->matchedRules);
        $this->assertEqualsCanonicalizing(
            array_column($this->verdict([], ['id' => $payload])->matchedRules, 'id'),
            array_column($crsVerdict->matchedRules, 'id'),
            'The same rules should fire whether or not the name is shadowed.'
        );
    }

    public function testPayloadInQueryIsStillDetectedBehindABenignPostParam(): void
    {
        $crsVerdict = $this->verdict(['id' => "' OR 1=1 -- "], ['id' => 'harmless']);

        $this->assertTrue($crsVerdict->isBlocked(), 'The reverse direction must hold too.');
    }

    public function testCleanRequestWithCollidingNamesStillPasses(): void
    {
        $crsVerdict = $this->verdict(['page' => '2'], ['page' => '3']);

        $this->assertFalse(
            $crsVerdict->isBlocked(),
            'Duplicated names are ordinary in web forms and must not block on their own.'
        );
    }

    /**
     * @param array<string, string> $get
     * @param array<string, string> $post
     */
    private function verdict(array $get, array $post): CrsVerdict
    {
        $body = http_build_query($post);

        return $this->crsEngine->evaluate(new RequestData(
            method: 'POST',
            uri: '/index.php',
            rawUri: '/index.php',
            queryString: http_build_query($get),
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            queryArgs: $get,
            postArgs: $post,
            headers: [
                'host'           => 'example.test',
                'content-type'   => 'application/x-www-form-urlencoded',
                'content-length' => (string) strlen($body),
            ],
            body: $body,
        ));
    }
}

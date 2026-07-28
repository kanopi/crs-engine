<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\CrsVerdict;
use Kanopi\Crs\Request\RequestData;
use PHPUnit\Framework\TestCase;

/**
 * CRS switches a rule off for traffic it knows will trip it, using
 * ctl:ruleRemoveById on an earlier guard rule. Ignoring that turned a rule
 * upstream disables into one that fires on ordinary traffic.
 *
 * 920540 flags `\uXXXX` as a Unicode bypass attempt. In JSON that is ordinary
 * string escaping — every accented character and emoji is written that way — so
 * 920539 checks REQBODY_PROCESSOR for JSON and removes 920540. Without it, any
 * JSON API carrying a non-ASCII character was rejected at default config.
 */
final class CtlRuleRemovalTest extends TestCase
{
    private CrsEngine $crsEngine;

    /** A literal backslash-u escape, built so no source encoding can flatten it. */
    private string $escaped;

    protected function setUp(): void
    {
        $this->crsEngine = new CrsEngine(new CrsConfig(paranoia: 1));
        $this->escaped   = '{"name":"Jos' . chr(92) . 'u00e9 Garc' . chr(92) . 'u00eda"}';
    }

    /**
     * @param array<string, string> $args
     */
    private function verdict(string $body, string $contentType, array $args = [], ?string $processor = null): CrsVerdict
    {
        return $this->crsEngine->evaluate(new RequestData(
            method: 'POST',
            uri: '/api/items',
            rawUri: '/api/items',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            postArgs: $args,
            headers: [
                'host'           => 'api.example.test',
                'content-type'   => $contentType,
                'content-length' => (string) strlen($body),
            ],
            body: $body,
            bodyProcessor: $processor,
        ));
    }

    public function testTheFixtureReallyMatches920540(): void
    {
        $this->assertMatchesRegularExpression(
            '/(?i)\x5cu[0-9a-f]{4}/',
            $this->escaped,
            'The rest of this class is meaningless if the payload stops looking like a \\uXXXX escape.'
        );
    }

    public function testAJsonBodyWithUnicodeEscapesIsNotRejected(): void
    {
        $crsVerdict = $this->verdict($this->escaped, 'application/json');

        $this->assertFalse($crsVerdict->isBlocked(), 'JSON escapes are ordinary, not an evasion attempt.');
        $this->assertNotContains(920540, array_column($crsVerdict->matchedRules, 'id'));
    }

    public function testAnExplicitJsonBodyProcessorAlsoSuppresses(): void
    {
        $crsVerdict = $this->verdict($this->escaped, 'text/plain', processor: 'JSON');

        $this->assertFalse($crsVerdict->isBlocked(), 'An integrator-supplied processor must work too.');
    }

    /**
     * Fidelity, not an oversight: with no JSON body processor there is nothing
     * to trigger 920539, so upstream CRS flags this too. It needs a per-site
     * exclusion rather than an engine change.
     */
    public function testTheSameBytesInAFormFieldAreStillFlagged(): void
    {
        $crsVerdict = $this->verdict(
            'data=' . rawurlencode($this->escaped),
            'application/x-www-form-urlencoded',
            ['data' => $this->escaped],
        );

        $this->assertContains(920540, array_column($crsVerdict->matchedRules, 'id'));
    }

    public function testSuppressionDoesNotLeakIntoTheNextRequest(): void
    {
        $this->verdict($this->escaped, 'application/json');
        $crsVerdict = $this->verdict(
            'data=' . rawurlencode($this->escaped),
            'application/x-www-form-urlencoded',
            ['data' => $this->escaped],
        );

        $this->assertContains(
            920540,
            array_column($crsVerdict->matchedRules, 'id'),
            'ctl is scoped to one transaction; a JSON request must not disarm the next one.'
        );
    }

    public function testRealAttacksInJsonAreStillCaught(): void
    {
        $sqli = ['q' => "1' UNION ALL SELECT 1,2,3,4 -- "];
        $xss  = ['q' => '<script>alert(1)</script>'];

        $this->assertTrue($this->verdict((string) json_encode($sqli), 'application/json', $sqli)->isBlocked());
        $this->assertTrue($this->verdict((string) json_encode($xss), 'application/json', $xss)->isBlocked());
    }

    /**
     * Suppressing 920540 must not suppress anything else in the 920 series.
     */
    public function testOnlyTheNamedRuleIsRemoved(): void
    {
        $body = $this->escaped;
        $crsVerdict = $this->crsEngine->evaluate(new RequestData(
            method: 'TRACE',
            uri: '/api/items',
            rawUri: '/api/items',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            headers: ['host' => 'api.example.test', 'content-type' => 'application/json', 'content-length' => (string) strlen($body)],
            body: $body,
        ));

        $this->assertContains(
            911100,
            array_column($crsVerdict->matchedRules, 'id'),
            'Method enforcement is unrelated and must still fire.'
        );
    }

    public function testBodyProcessorIsInferredFromContentType(): void
    {
        $requestData = new RequestData(
            method: 'POST',
            uri: '/',
            rawUri: '/',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            headers: ['content-type' => 'application/vnd.api+json; charset=utf-8'],
        );

        $this->assertSame('JSON', $requestData->effectiveBodyProcessor());
    }

    public function testAnExplicitBodyProcessorWinsOverInference(): void
    {
        $requestData = new RequestData(
            method: 'POST',
            uri: '/',
            rawUri: '/',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            headers: ['content-type' => 'application/json'],
            bodyProcessor: 'RAW',
        );

        $this->assertSame('RAW', $requestData->effectiveBodyProcessor());
    }

    public function testAnUnknownContentTypeInfersNothing(): void
    {
        $requestData = new RequestData(
            method: 'POST',
            uri: '/',
            rawUri: '/',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            headers: ['content-type' => 'application/octet-stream'],
        );

        $this->assertNull($requestData->effectiveBodyProcessor());
    }
}

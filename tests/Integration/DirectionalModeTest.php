<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\CrsVerdict;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Request\ResponseData;
use PHPUnit\Framework\TestCase;

/**
 * Request and response can run in different modes.
 *
 * Blocking outbound is a much heavier action than blocking inbound: the
 * application has already done its work, and rejecting the response means
 * serving an error in place of a page that is very likely fine. The posture a
 * CMS usually wants is reject attacks on the way in, record leakage on the way
 * out — which a single shared `mode` could not express.
 */
final class DirectionalModeTest extends TestCase
{
    private const SQLI  = "' OR 1=1 -- ";

    private const LEAK  = "<b>Warning</b>: You have an error in your SQL syntax near 'x' at line 1";

    private function request(): RequestData
    {
        $args = ['q' => self::SQLI];
        $body = http_build_query($args);

        return new RequestData(
            method: 'POST',
            uri: '/search',
            rawUri: '/search',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            postArgs: $args,
            headers: [
                'host'           => 'example.test',
                'content-type'   => 'application/x-www-form-urlencoded',
                'content-length' => (string) strlen($body),
            ],
            body: $body,
        );
    }

    private function cleanRequest(): RequestData
    {
        return new RequestData(
            method: 'GET',
            uri: '/page',
            rawUri: '/page',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            headers: ['host' => 'example.test'],
        );
    }

    private function response(): ResponseData
    {
        return new ResponseData(status: 500, headers: ['content-type' => 'text/html'], body: self::LEAK);
    }

    private function inbound(CrsConfig $crsConfig): CrsVerdict
    {
        return (new CrsEngine($crsConfig))->evaluate($this->request());
    }

    private function outbound(CrsConfig $crsConfig): CrsVerdict
    {
        return (new CrsEngine($crsConfig))->evaluateResponse($this->cleanRequest(), $this->response());
    }

    /**
     * `mode` governs the request. Outbound does not follow it, because a single
     * response-rule match is already over the outbound threshold and blocking a
     * response is heavier than rejecting a request — see
     * CrsConfig::DEFAULT_RESPONSE_MODE.
     */
    public function testModeGovernsTheRequestAndOutboundDefaultsToMonitor(): void
    {
        $crsConfig = new CrsConfig(paranoia: 1, mode: CrsConfig::MODE_BLOCK);

        $this->assertSame(CrsConfig::MODE_BLOCK, $crsConfig->requestMode);
        $this->assertSame(CrsConfig::MODE_MONITOR, $crsConfig->responseMode);
        $this->assertTrue($this->inbound($crsConfig)->isBlocked());
        $this->assertFalse($this->outbound($crsConfig)->isBlocked());
    }

    public function testOutboundBlockingIsAvailableByOptingIn(): void
    {
        $crsConfig = new CrsConfig(
            paranoia: 1,
            mode: CrsConfig::MODE_BLOCK,
            responseMode: CrsConfig::MODE_BLOCK,
        );

        $this->assertTrue($this->outbound($crsConfig)->isBlocked());
    }

    public function testMonitorModeGovernsBothDirections(): void
    {
        $crsConfig = new CrsConfig(paranoia: 1, mode: CrsConfig::MODE_MONITOR);

        $this->assertFalse($this->inbound($crsConfig)->isBlocked());
        $this->assertFalse($this->outbound($crsConfig)->isBlocked());
    }

    /**
     * The posture this exists for.
     */
    public function testBlockInboundWhileOnlyRecordingOutbound(): void
    {
        $crsConfig = new CrsConfig(
            paranoia: 1,
            mode: CrsConfig::MODE_BLOCK,
            responseMode: CrsConfig::MODE_MONITOR,
        );

        $inbound  = $this->inbound($crsConfig);
        $outbound = $this->outbound($crsConfig);

        $this->assertTrue($inbound->isBlocked(), 'Attacks on the way in should still be rejected.');

        $this->assertFalse($outbound->isBlocked(), 'Leakage on the way out should not break the page.');
        $this->assertSame(CrsVerdict::ACTION_LOG, $outbound->action);
        $this->assertNotEmpty($outbound->matchedRules, 'It still has to be detected and reported.');
        $this->assertGreaterThan(0, $outbound->totalScore);
    }

    public function testTheReverseAlsoHolds(): void
    {
        $crsConfig = new CrsConfig(
            paranoia: 1,
            mode: CrsConfig::MODE_MONITOR,
            responseMode: CrsConfig::MODE_BLOCK,
        );

        $this->assertFalse($this->inbound($crsConfig)->isBlocked());
        $this->assertTrue($this->outbound($crsConfig)->isBlocked());
    }

    public function testRequestModeOverridesIndependently(): void
    {
        $crsConfig = new CrsConfig(
            paranoia: 1,
            mode: CrsConfig::MODE_BLOCK,
            requestMode: CrsConfig::MODE_MONITOR,
            responseMode: CrsConfig::MODE_BLOCK,
        );

        $this->assertFalse($this->inbound($crsConfig)->isBlocked());
        $this->assertTrue($this->outbound($crsConfig)->isBlocked());
    }

    public function testModesComeThroughFromArray(): void
    {
        $crsConfig = CrsConfig::fromArray([
            'mode'          => 'block',
            'response_mode' => 'monitor',
        ]);

        $this->assertSame(CrsConfig::MODE_BLOCK, $crsConfig->requestMode);
        $this->assertSame(CrsConfig::MODE_MONITOR, $crsConfig->responseMode);
    }

    public function testModeForMirrorsThresholdFor(): void
    {
        $crsConfig = new CrsConfig(mode: CrsConfig::MODE_BLOCK, responseMode: CrsConfig::MODE_MONITOR);

        $this->assertSame(CrsConfig::MODE_BLOCK, $crsConfig->modeFor(requestPhase: true));
        $this->assertSame(CrsConfig::MODE_MONITOR, $crsConfig->modeFor(requestPhase: false));
    }

    public function testAnInvalidDirectionalModeIsRejected(): void
    {
        $this->expectException(\Kanopi\Crs\Exception\ConfigurationException::class);
        $this->expectExceptionMessageMatches('/responseMode/');

        new CrsConfig(responseMode: 'sometimes');
    }
}

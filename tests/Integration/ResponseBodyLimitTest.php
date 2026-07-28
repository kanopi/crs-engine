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
 * The response body gets its own inspection limit.
 *
 * One knob governed both directions, defaulted to ModSecurity's
 * SecRequestBodyNoFilesLimit (131072) — a request figure. A 128 KB request body
 * is large; a 128 KB HTML page is ordinary, so the 165 response-phase rules
 * stopped seeing anything past that point on a normal page. Leaked stack
 * traces, SQL errors and debug dumps cluster in exactly that tail, appended
 * after the content or emitted in a footer.
 */
final class ResponseBodyLimitTest extends TestCase
{
    private const LEAK = "<b>Warning</b>: You have an error in your SQL syntax near 'x' at line 1";

    private RequestData $requestData;

    protected function setUp(): void
    {
        $this->requestData = new RequestData(
            method: 'GET',
            uri: '/page',
            rawUri: '/page',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            headers: ['host' => 'example.test'],
        );
    }

    private function page(int $approxBytes, bool $leakAtEnd): string
    {
        $filler = str_repeat("<p>ordinary page content</p>\n", (int) ceil($approxBytes / 29));

        return $leakAtEnd ? $filler . self::LEAK : self::LEAK . $filler;
    }

    private function verdict(string $body, ?CrsConfig $crsConfig = null): CrsVerdict
    {
        // Outbound defaults to monitor, so these assert on isBlocked() only
        // because they opt into outbound blocking — what is under test is which
        // bytes the rules were shown, not the mode.
        $crsConfig ??= new CrsConfig(paranoia: 1, responseMode: CrsConfig::MODE_BLOCK);

        return (new CrsEngine($crsConfig))->evaluateResponse(
            $this->requestData,
            new ResponseData(status: 500, headers: ['content-type' => 'text/html'], body: $body),
        );
    }

    public function testTheDefaultsAreDirectionalAndTheResponseOneIsLarger(): void
    {
        $crsConfig = new CrsConfig();

        $this->assertSame(131072, $crsConfig->maxRequestBodyBytes);
        $this->assertSame(524288, $crsConfig->maxResponseBodyBytes);
        $this->assertGreaterThan(
            $crsConfig->maxRequestBodyBytes,
            $crsConfig->maxResponseBodyBytes,
            'A response body is routinely larger than a request body.'
        );
    }

    /**
     * The regression. 169 KB is an unremarkable page; under the old shared
     * 128 KB cap a leak in its tail was invisible.
     */
    public function testALeakInTheTailOfAnOrdinaryPageIsFound(): void
    {
        $body = $this->page(169 * 1024, leakAtEnd: true);
        $crsVerdict = $this->verdict($body);

        $this->assertGreaterThan(131072, strlen($body), 'The fixture has to exceed the old shared cap.');
        $this->assertTrue($crsVerdict->isBlocked(), 'A leak past 128 KB of a normal page must still be caught.');
        $this->assertContains(951230, array_column($crsVerdict->matchedRules, 'id'));
        $this->assertFalse($crsVerdict->wasTruncated(), 'A 169 KB page is under the response limit.');
    }

    public function testALeakAtTheHeadOfAnOrdinaryPageIsFound(): void
    {
        $crsVerdict = $this->verdict($this->page(169 * 1024, leakAtEnd: false));

        $this->assertTrue($crsVerdict->isBlocked());
    }

    public function testACleanOrdinaryPageStillPasses(): void
    {
        $crsVerdict = $this->verdict(str_repeat("<p>ordinary page content</p>\n", 6000));

        $this->assertFalse($crsVerdict->isBlocked());
        $this->assertFalse($crsVerdict->wasTruncated());
    }

    /**
     * The response limit is larger, not absent — the point of #33 was that an
     * unbounded body is unbounded work, and that applies outbound too.
     */
    public function testAResponseBeyondTheResponseLimitIsStillTruncated(): void
    {
        $crsVerdict = $this->verdict($this->page(700 * 1024, leakAtEnd: true));

        $this->assertTrue($crsVerdict->wasTruncated());
        $this->assertSame('response_body', $crsVerdict->truncations[0]['what']);
        $this->assertSame(524288, $crsVerdict->truncations[0]['inspected']);
    }

    public function testTheRequestLimitDoesNotGovernTheResponse(): void
    {
        // A tiny request limit must leave response inspection untouched.
        $crsConfig = new CrsConfig(paranoia: 1, maxRequestBodyBytes: 64, responseMode: CrsConfig::MODE_BLOCK);
        $crsVerdict = $this->verdict($this->page(169 * 1024, leakAtEnd: true), $crsConfig);

        $this->assertTrue($crsVerdict->isBlocked());
        $this->assertFalse($crsVerdict->wasTruncated());
    }

    public function testTheResponseLimitDoesNotGovernTheRequest(): void
    {
        // ...and the converse: a tiny response limit must not shrink request
        // inspection. The payload sits past 64 bytes of the request body.
        $crsConfig = new CrsConfig(paranoia: 1, maxResponseBodyBytes: 64);
        $args = ['pad' => str_repeat('a', 500), 'q' => "' OR 1=1 -- "];
        $body = http_build_query($args);

        $crsVerdict = (new CrsEngine($crsConfig))->evaluate(new RequestData(
            method: 'POST',
            uri: '/',
            rawUri: '/',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            postArgs: $args,
            headers: ['host' => 'x', 'content-type' => 'application/x-www-form-urlencoded', 'content-length' => (string) strlen($body)],
            body: $body,
        ));

        $this->assertTrue($crsVerdict->isBlocked());
    }

    public function testUnlimitedResponseBodyInspectsEverything(): void
    {
        $crsConfig = new CrsConfig(paranoia: 1, maxResponseBodyBytes: CrsConfig::UNLIMITED, responseMode: CrsConfig::MODE_BLOCK);
        $crsVerdict = $this->verdict($this->page(700 * 1024, leakAtEnd: true), $crsConfig);

        $this->assertFalse($crsVerdict->wasTruncated());
        $this->assertTrue($crsVerdict->isBlocked());
    }
}

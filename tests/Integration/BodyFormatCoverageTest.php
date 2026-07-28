<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\CrsVerdict;
use Kanopi\Crs\Request\RequestData;
use PHPUnit\Framework\TestCase;

/**
 * What each body format gets inspected as, across the board.
 *
 * 187 CRS rules target ARGS and 19 read REQUEST_BODY, so a structured body that
 * does not reach ARGS is a body the ruleset barely inspects — and it does not
 * matter which format left it there. This is the matrix, so a format cannot
 * quietly fall out of it.
 *
 * The payload is an XSS string rather than a SQL tautology on purpose: the
 * supplemental tautology rule also targets REQUEST_BODY, so it scores on every
 * format and would hide the differences this test exists to show.
 */
final class BodyFormatCoverageTest extends TestCase
{
    private const PAYLOAD = '<script>alert(1)</script>';

    private const BOUNDARY = '----XbodyFormatTest';

    private CrsEngine $crsEngine;

    protected function setUp(): void
    {
        $this->crsEngine = new CrsEngine(new CrsConfig(paranoia: 1));
    }

    /**
     * @param array<string, string> $postArgs
     */
    private function verdict(string $contentType, string $body, array $postArgs = []): CrsVerdict
    {
        return $this->crsEngine->evaluate(new RequestData(
            method: 'POST',
            uri: '/submit',
            rawUri: '/submit',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            postArgs: $postArgs,
            headers: [
                'host'           => 'example.test',
                'content-type'   => $contentType,
                'content-length' => (string) strlen($body),
            ],
            body: $body,
        ));
    }

    private function multipartBody(): string
    {
        return "--" . self::BOUNDARY . "\r\n"
            . "Content-Disposition: form-data; name=\"q\"\r\n\r\n"
            . self::PAYLOAD . "\r\n--" . self::BOUNDARY . "--\r\n";
    }

    /**
     * The formats the engine parses into ARGS itself, with no help.
     *
     * @return \Iterator<string, array{string, string}>
     */
    public static function selfParsingFormatProvider(): \Iterator
    {
        yield 'urlencoded' => ['application/x-www-form-urlencoded', 'q=' . rawurlencode(self::PAYLOAD)];
        yield 'json' => ['application/json', '{"q":"<script>alert(1)<\/script>"}'];
        yield 'json vendor type' => ['application/vnd.api+json', '{"q":"<script>alert(1)<\/script>"}'];
        yield 'xml' => ['application/xml', '<?xml version="1.0"?><r><q>&lt;script&gt;alert(1)&lt;/script&gt;</q></r>'];
        yield 'text/xml' => ['text/xml', '<?xml version="1.0"?><r><q>&lt;script&gt;alert(1)&lt;/script&gt;</q></r>'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('selfParsingFormatProvider')]
    public function testFormatsTheEngineParsesAreFullyInspected(string $contentType, string $body): void
    {
        $crsVerdict = $this->verdict($contentType, $body);

        $this->assertTrue($crsVerdict->isBlocked(), $contentType . ' should reach ARGS without integrator help.');
        $this->assertFalse($crsVerdict->wasTruncated(), 'Nothing was skipped, so nothing should be reported.');
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('selfParsingFormatProvider')]
    public function testParsingAgreesWithAnIntegratorSuppliedDecode(string $contentType, string $body): void
    {
        $this->assertSame(
            $this->verdict($contentType, $body, ['q' => self::PAYLOAD])->totalScore,
            $this->verdict($contentType, $body)->totalScore,
            'Whether the integrator decoded the body should not change the verdict.'
        );
    }

    /**
     * Multipart is left to the integrator: boundaries, part headers, transfer
     * encodings and file parts are a real parser, and it is the format where
     * disagreeing subtly with the application creates bypasses rather than
     * closing them. CRS's own multipart support is fed from multipartFlags,
     * multipartPartHeaders and files, which the engine already accepts.
     *
     * What must not happen is it being silent about it.
     */
    public function testMultipartIsNotParsedButIsReported(): void
    {
        $crsVerdict = $this->verdict('multipart/form-data; boundary=' . self::BOUNDARY, $this->multipartBody());

        $this->assertTrue($crsVerdict->wasTruncated(), 'Nothing reached ARGS; that has to be visible.');
        $this->assertSame('multipart_body_unparsed', $crsVerdict->truncations[0]['what']);
    }

    public function testMultipartIsFullyInspectedWhenTheIntegratorSuppliesArgs(): void
    {
        $crsVerdict = $this->verdict(
            'multipart/form-data; boundary=' . self::BOUNDARY,
            $this->multipartBody(),
            ['q' => self::PAYLOAD],
        );

        $this->assertTrue($crsVerdict->isBlocked());
        $this->assertFalse($crsVerdict->wasTruncated(), 'Args were supplied, so there is no gap to report.');
    }

    /**
     * Unstructured bodies have nothing to flatten. REQUEST_BODY still inspects
     * them as raw text, which is the right treatment — and reporting a
     * "coverage gap" here would be noise, because there is no action to take.
     *
     * @return \Iterator<string, array{string}>
     */
    public static function unstructuredFormatProvider(): \Iterator
    {
        yield 'text/plain' => ['text/plain'];
        yield 'octet-stream' => ['application/octet-stream'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('unstructuredFormatProvider')]
    public function testUnstructuredBodiesAreReadRawAndNotReportedAsAGap(string $contentType): void
    {
        $crsVerdict = $this->verdict($contentType, self::PAYLOAD);

        $this->assertGreaterThan(0, $crsVerdict->totalScore, 'REQUEST_BODY should still see it.');
        $this->assertFalse($crsVerdict->wasTruncated(), 'There is nothing to parse, so nothing to report.');
    }

    /**
     * A urlencoded body is just text containing `=` and `&`, and plenty of
     * non-form bodies contain both. Guessing would chop prose into nonsense
     * arguments and inspect the pieces, which invents findings.
     */
    public function testAPlainTextBodyIsNotGuessedIntoArguments(): void
    {
        $requestData = new RequestData(
            method: 'POST',
            uri: '/submit',
            rawUri: '/submit',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            headers: ['host' => 'x', 'content-type' => 'text/plain'],
            body: 'subject=hello&body=world',
        );

        $names = (new \Kanopi\Crs\Variables\VariableResolver(new \Kanopi\Crs\Runtime\TxStore()))
            ->resolve([['collection' => 'ARGS_NAMES']], $requestData);

        $this->assertSame([], $names, 'Only the declared Content-Type decides, never the shape.');
    }

    public function testUrlEncodedNestedNamesFlattenTheSameWayPostArgsDo(): void
    {
        $requestData = new RequestData(
            method: 'POST',
            uri: '/submit',
            rawUri: '/submit',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            headers: ['host' => 'x', 'content-type' => 'application/x-www-form-urlencoded'],
            body: 'user%5Bemail%5D=a%40b.test&plain=1',
        );

        $values = array_map(
            static fn (\Kanopi\Crs\Variables\ResolvedValue $resolvedValue): string => $resolvedValue->value,
            (new \Kanopi\Crs\Variables\VariableResolver(new \Kanopi\Crs\Runtime\TxStore()))
                ->resolve([['collection' => 'ARGS']], $requestData),
        );

        $this->assertContains('a@b.test', $values);
        $this->assertContains('1', $values);
    }

    public function testAnOrdinaryFormPostStillPasses(): void
    {
        $body = http_build_query([
            'name'    => 'Ada Lovelace',
            'email'   => 'ada@example.test',
            'message' => 'Please send a quote for 30 units.',
        ]);

        $crsVerdict = $this->verdict('application/x-www-form-urlencoded', $body);

        $this->assertFalse($crsVerdict->isBlocked());
        $this->assertSame(0, $crsVerdict->totalScore);
    }
}

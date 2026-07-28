<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Body;

use Kanopi\Crs\Body\JsonBody;
use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\Request\RequestData;
use PHPUnit\Framework\TestCase;

/**
 * Flattening a JSON body into ARGS.
 *
 * 187 CRS rules target ARGS and 19 target REQUEST_BODY, so a JSON body that
 * never reaches ARGS is a body the ruleset barely inspects.
 */
final class JsonBodyTest extends TestCase
{
    private function body(string $json, string $contentType = 'application/json'): JsonBody
    {
        return new JsonBody(
            new RequestData(
                method: 'POST',
                uri: '/api',
                rawUri: '/api',
                queryString: '',
                protocol: 'HTTP/1.1',
                remoteAddr: '127.0.0.1',
                headers: ['content-type' => $contentType],
                body: $json,
            ),
            CrsConfig::UNLIMITED,
        );
    }

    public function testFlatKeysTakeTheJsonPrefix(): void
    {
        $this->assertSame(['json.q' => 'payload'], $this->body('{"q":"payload"}')->args());
    }

    /**
     * ModSecurity's naming, so an exclusion written against upstream variable
     * names still refers to the same thing here.
     */
    public function testNestedObjectsBecomeDottedPaths(): void
    {
        $this->assertSame(
            ['json.user.name' => 'Ada', 'json.user.address.city' => 'London'],
            $this->body('{"user":{"name":"Ada","address":{"city":"London"}}}')->args()
        );
    }

    public function testArrayElementsTakeTheirIndex(): void
    {
        $this->assertSame(
            ['json.tags.0' => 'a', 'json.tags.1' => 'b'],
            $this->body('{"tags":["a","b"]}')->args()
        );
    }

    public function testATopLevelArrayIsFlattenedToo(): void
    {
        $this->assertSame(['json.0' => 'x', 'json.1' => 'y'], $this->body('["x","y"]')->args());
    }

    public function testNonStringScalarsAreStringified(): void
    {
        $this->assertSame(
            ['json.n' => '42', 'json.f' => '1.5', 'json.t' => 'true', 'json.no' => 'false', 'json.nil' => ''],
            $this->body('{"n":42,"f":1.5,"t":true,"no":false,"nil":null}')->args()
        );
    }

    public function testMalformedJsonIsReportedRatherThanSwallowed(): void
    {
        $jsonBody = $this->body('{"q":"unterminated');

        $this->assertTrue($jsonBody->failedToParse());
        $this->assertSame([], $jsonBody->args());
    }

    public function testABareScalarBodyYieldsNoArgsAndIsNotAFailure(): void
    {
        // Valid JSON, nothing to flatten. REQUEST_BODY still sees it.
        $jsonBody = $this->body('"just a string"');

        $this->assertSame([], $jsonBody->args());
        $this->assertFalse($jsonBody->failedToParse());
    }

    public function testContentTypeIsEnoughToTryEvenWithoutBraces(): void
    {
        $this->assertTrue($this->body('123', 'application/json')->isLikelyJson());
        $this->assertTrue($this->body('{"a":1}', 'application/vnd.api+json')->isLikelyJson());
    }

    public function testAShapeLikeBodyIsTriedWithoutTheHeader(): void
    {
        $this->assertTrue($this->body('{"a":1}', 'text/plain')->isLikelyJson());
        $this->assertTrue($this->body('  ["a"]', 'text/plain')->isLikelyJson());
    }

    public function testAFormBodyIsNotMistakenForJson(): void
    {
        $this->assertFalse($this->body('a=1&b=2', 'application/x-www-form-urlencoded')->isLikelyJson());
        $this->assertFalse($this->body('', 'application/json')->isLikelyJson());
    }

    public function testAnOversizedBodyIsNotParsed(): void
    {
        $json = '{"q":"' . str_repeat('a', 500) . '"}';
        $jsonBody = new JsonBody(
            new RequestData(
                method: 'POST',
                uri: '/api',
                rawUri: '/api',
                queryString: '',
                protocol: 'HTTP/1.1',
                remoteAddr: '127.0.0.1',
                headers: ['content-type' => 'application/json'],
                body: $json,
            ),
            maxBytes: 50,
        );

        $this->assertSame([], $jsonBody->args(), 'A truncated document is not a document.');
        $this->assertFalse($jsonBody->failedToParse(), 'Refused is not the same as malformed.');
    }

    public function testFlatteningIsBoundedSoOneRequestCannotRunAway(): void
    {
        $wide = [];
        for ($i = 0; $i < 200; $i++) {
            $wide['k' . $i] = 'v';
        }

        $jsonBody = new JsonBody(
            new RequestData(
                method: 'POST',
                uri: '/api',
                rawUri: '/api',
                queryString: '',
                protocol: 'HTTP/1.1',
                remoteAddr: '127.0.0.1',
                headers: ['content-type' => 'application/json'],
                body: (string) json_encode($wide),
            ),
            maxBytes: CrsConfig::UNLIMITED,
            maxEntries: 50,
        );

        $this->assertCount(50, $jsonBody->args());
    }

    public function testDeeplyNestedJsonIsRefusedRatherThanRecursingForever(): void
    {
        $deep = str_repeat('{"a":', 200) . '1' . str_repeat('}', 200);

        $jsonBody = $this->body($deep);

        $this->assertTrue($jsonBody->failedToParse(), 'Depth beyond the limit is a parse failure, not a crash.');
        $this->assertSame([], $jsonBody->args());
    }

    public function testUnicodeEscapesAreDecodedByTheParser(): void
    {
        // json_decode resolves \uXXXX, so ARGS carries the character rather than
        // the escape — which is why 920540 does not see a Unicode bypass here.
        $args = $this->body('{"name":"Jos' . chr(92) . 'u00e9"}')->args();

        $this->assertSame(['json.name' => 'José'], $args);
    }
}

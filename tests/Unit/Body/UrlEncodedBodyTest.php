<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Body;

use Kanopi\Crs\Body\UrlEncodedBody;
use Kanopi\Crs\Request\RequestData;
use PHPUnit\Framework\TestCase;

/**
 * Decoding a urlencoded body into ARGS.
 *
 * The format most likely to hit the "nothing populated postArgs" gap by
 * accident: PHP fills $_POST for it, so fromGlobals() and framework request
 * objects carry the arguments — but a PSR-7 getParsedBody() returns null unless
 * something populated it.
 */
final class UrlEncodedBodyTest extends TestCase
{
    private function body(string $raw, string $contentType = 'application/x-www-form-urlencoded'): UrlEncodedBody
    {
        return new UrlEncodedBody(new RequestData(
            method: 'POST',
            uri: '/submit',
            rawUri: '/submit',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            headers: ['content-type' => $contentType],
            body: $raw,
        ));
    }

    public function testSimplePairsAreDecoded(): void
    {
        $this->assertSame(['a' => '1', 'b' => 'two'], $this->body('a=1&b=two')->args());
    }

    public function testPercentEncodingIsDecoded(): void
    {
        $this->assertSame(['q' => 'a b&c'], $this->body('q=a%20b%26c')->args());
    }

    public function testBracketNamesBecomeNestedArraysAsPhpDoes(): void
    {
        $this->assertSame(['user' => ['email' => 'a@b.test']], $this->body('user%5Bemail%5D=a%40b.test')->args());
    }

    /**
     * parse_str mangles `a.b` to `a_b`, and so does PHP when it fills $_POST.
     * The application on the other end is a PHP application, so matching that
     * mangling is what keeps the engine and the application looking at the same
     * thing — a stricter parser would disagree with the app.
     */
    public function testNameManglingMatchesPhpsOwn(): void
    {
        $this->assertSame(['a_b' => '1'], $this->body('a.b=1')->args());
    }

    /**
     * Content-Type decides, never the shape. A urlencoded body is just text with
     * `=` and `&` in it, and plenty of non-form bodies contain both — guessing
     * would chop prose into arguments and inspect the pieces.
     *
     * @return \Iterator<string, array{string}>
     */
    public static function nonFormContentTypeProvider(): \Iterator
    {
        yield 'plain text' => ['text/plain'];
        yield 'json' => ['application/json'];
        yield 'octet stream' => ['application/octet-stream'];
        yield 'absent' => [''];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('nonFormContentTypeProvider')]
    public function testOnlyTheDeclaredContentTypeCounts(string $contentType): void
    {
        $urlEncodedBody = $this->body('subject=hello&body=world', $contentType);

        $this->assertFalse($urlEncodedBody->isLikelyUrlEncoded());
        $this->assertSame([], $urlEncodedBody->args());
    }

    public function testCharsetParameterDoesNotDefeatDetection(): void
    {
        $this->assertTrue(
            $this->body('a=1', 'application/x-www-form-urlencoded; charset=utf-8')->isLikelyUrlEncoded()
        );
    }

    public function testAnEmptyBodyYieldsNothing(): void
    {
        $urlEncodedBody = $this->body('');

        $this->assertFalse($urlEncodedBody->isLikelyUrlEncoded());
        $this->assertSame([], $urlEncodedBody->args());
    }
}

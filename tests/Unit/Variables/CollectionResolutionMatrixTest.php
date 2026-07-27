<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Variables;

use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Request\ResponseData;
use Kanopi\Crs\Runtime\TxStore;
use Kanopi\Crs\Variables\ResolvedValue;
use Kanopi\Crs\Variables\VariableResolver;
use PHPUnit\Framework\TestCase;

/**
 * Coverage of the target collections the focused tests do not reach.
 *
 * A rule handed the wrong values is as broken as a rule that decides wrongly,
 * and that half of the engine has produced a shipped bypass once already —
 * ARGS resolving from a name-keyed union dropped POST values on collision.
 * These are the remaining collections, each exercised at least once so a
 * refactor cannot quietly stop resolving one.
 */
final class CollectionResolutionMatrixTest extends TestCase
{
    /**
     * @param array<int, ResolvedValue> $resolved
     * @return array<int, string>
     */
    private function values(array $resolved): array
    {
        return array_map(static fn (ResolvedValue $resolvedValue): string => $resolvedValue->value, $resolved);
    }

    /**
     * @return array<int, ResolvedValue>
     */
    private function resolve(string $collection, RequestData $requestData, ?string $selector = null, bool $regex = false, ?ResponseData $responseData = null): array
    {
        $target = ['collection' => $collection];
        if ($selector !== null) {
            $target['selector'] = $selector;
            $target['regex'] = $regex;
        }

        return (new VariableResolver(new TxStore(), $responseData))->resolve([$target], $requestData);
    }

    private function request(): RequestData
    {
        return new RequestData(
            method: 'POST',
            uri: '/app/index.php?a=1',
            rawUri: '/app/index.php?a=1',
            queryString: 'a=1',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            queryArgs: ['a' => '1'],
            postArgs: ['b' => '2', 'user' => ['email' => 'ada@example.test', 'tags' => ['x', 'y']]],
            cookies: ['sid' => 'abc'],
            headers: ['host' => 'example.test', 'accept' => ['text/html', 'application/json']],
            body: 'b=2',
            files: [
                ['name' => 'avatar', 'filename' => 'photo.jpg', 'size' => 1024, 'content' => 'JPEGDATA'],
            ],
        );
    }

    public function testArgsPostNames(): void
    {
        $this->assertSame(['b', 'user'], $this->values($this->resolve('ARGS_POST_NAMES', $this->request())));
    }

    public function testArgsGetNames(): void
    {
        $this->assertSame(['a'], $this->values($this->resolve('ARGS_GET_NAMES', $this->request())));
    }

    public function testRemoteAddr(): void
    {
        $this->assertSame(['203.0.113.9'], $this->values($this->resolve('REMOTE_ADDR', $this->request())));
    }

    public function testRequestLineAndProtocol(): void
    {
        $this->assertSame(['HTTP/1.1'], $this->values($this->resolve('REQUEST_PROTOCOL', $this->request())));
        $this->assertSame(
            ['POST /app/index.php?a=1 HTTP/1.1'],
            $this->values($this->resolve('REQUEST_LINE', $this->request()))
        );
    }

    public function testRequestFilenameAndBasename(): void
    {
        $this->assertSame(['/app/index.php'], $this->values($this->resolve('REQUEST_FILENAME', $this->request())));
        $this->assertSame(['index.php'], $this->values($this->resolve('REQUEST_BASENAME', $this->request())));
    }

    public function testCookiesAndCookieNames(): void
    {
        $this->assertSame(['abc'], $this->values($this->resolve('REQUEST_COOKIES', $this->request())));
        $this->assertSame(['sid'], $this->values($this->resolve('REQUEST_COOKIES_NAMES', $this->request())));
    }

    /**
     * A nested argument bag is flattened one level so ARGS:user[email] resolves;
     * anything deeper falls back to a serialised representation rather than
     * being dropped, because a payload hidden in a deep array still has to be
     * inspected.
     */
    public function testNestedArgumentsAreFlattened(): void
    {
        $values = $this->resolve('ARGS', $this->request());

        $this->assertContains('ada@example.test', $this->values($values));
        $this->assertContains('["x","y"]', $this->values($values), 'Deeper nesting should serialise, not vanish.');
    }

    public function testAMultiValuedHeaderYieldsEachValue(): void
    {
        $values = $this->resolve('REQUEST_HEADERS', $this->request(), 'accept');

        $this->assertSame(['text/html', 'application/json'], $this->values($values));
    }

    public function testHeaderSelectorIsCaseInsensitive(): void
    {
        $this->assertSame(
            ['example.test'],
            $this->values($this->resolve('REQUEST_HEADERS', $this->request(), 'HOST'))
        );
    }

    public function testHeaderSelectorAcceptsARegex(): void
    {
        $values = $this->resolve('REQUEST_HEADERS', $this->request(), '^(host|accept)$', regex: true);

        $this->assertCount(3, $values, 'host plus both accept values.');
    }

    public function testFilesCollections(): void
    {
        $requestData = $this->request();

        $this->assertSame(['photo.jpg'], $this->values($this->resolve('FILES_NAMES', $requestData)));
        $this->assertSame(['1024'], $this->values($this->resolve('FILES_SIZES', $requestData)));
        $this->assertSame(['JPEGDATA'], $this->values($this->resolve('FILES', $requestData)));
    }

    public function testFileContentIsReadFromTmpNameWhenNotInlined(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'crs-upload-');
        $this->assertIsString($tmp);
        file_put_contents($tmp, '<?php echo "shell";');

        try {
            $requestData = new RequestData(
                method: 'POST',
                uri: '/',
                rawUri: '/',
                queryString: '',
                protocol: 'HTTP/1.1',
                remoteAddr: '127.0.0.1',
                files: [['name' => 'upload', 'filename' => 'x.php', 'tmp_name' => $tmp]],
            );

            $this->assertSame(['<?php echo "shell";'], $this->values($this->resolve('FILES', $requestData)));
            $this->assertSame([$tmp], $this->values($this->resolve('FILES_TMPNAMES', $requestData)));
        } finally {
            unlink($tmp);
        }
    }

    public function testAnUnreadableUploadIsSkippedRatherThanFatal(): void
    {
        $requestData = new RequestData(
            method: 'POST',
            uri: '/',
            rawUri: '/',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            files: [['name' => 'upload', 'filename' => 'x.php', 'tmp_name' => '/nonexistent/nope']],
        );

        $this->assertSame([], $this->resolve('FILES', $requestData));
    }

    public function testResponseCollections(): void
    {
        $responseData = new ResponseData(
            status: 500,
            protocol: 'HTTP/2',
            headers: ['content-type' => 'text/html; charset=utf-8'],
            body: 'SQL syntax error',
        );
        $requestData = $this->request();

        $this->assertSame(['500'], $this->values($this->resolve('RESPONSE_STATUS', $requestData, responseData: $responseData)));
        $this->assertSame(['HTTP/2'], $this->values($this->resolve('RESPONSE_PROTOCOL', $requestData, responseData: $responseData)));
        $this->assertSame(['SQL syntax error'], $this->values($this->resolve('RESPONSE_BODY', $requestData, responseData: $responseData)));
        $this->assertSame(['16'], $this->values($this->resolve('RESPONSE_CONTENT_LENGTH', $requestData, responseData: $responseData)));
        $this->assertSame(
            ['text/html; charset=utf-8'],
            $this->values($this->resolve('RESPONSE_CONTENT_TYPE', $requestData, responseData: $responseData))
        );
        $this->assertSame(['1'], $this->values($this->resolve('OUTBOUND_DATA_ERROR', $requestData, responseData: $responseData)));
        $this->assertSame(
            ['content-type'],
            $this->values($this->resolve('RESPONSE_HEADERS_NAMES', $requestData, responseData: $responseData))
        );
    }

    public function testResponseCollectionsAreEmptyWithoutAResponse(): void
    {
        foreach (['RESPONSE_STATUS', 'RESPONSE_PROTOCOL', 'RESPONSE_BODY', 'RESPONSE_HEADERS', 'RESPONSE_CONTENT_TYPE'] as $collection) {
            $this->assertSame([], $this->resolve($collection, $this->request()), $collection . ' needs a response.');
        }
    }

    public function testAnUnknownCollectionResolvesToNothing(): void
    {
        $this->assertSame([], $this->resolve('NOT_A_REAL_COLLECTION', $this->request()));
    }
}

<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Variables;

use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Runtime\TxStore;
use Kanopi\Crs\Variables\VariableResolver;
use PHPUnit\Framework\TestCase;

final class ExtendedTargetsTest extends TestCase
{
    public function testRequestBasename(): void
    {
        $req = $this->req(uri: '/wp-admin/setup-config.php?step=1');
        $variableResolver = new VariableResolver(new TxStore());
        $values = $variableResolver->resolve([['collection' => 'REQUEST_BASENAME']], $req);
        $this->assertCount(1, $values);
        $this->assertSame('setup-config.php', $values[0]->value);
    }

    public function testUniqueId(): void
    {
        $req = $this->req(uniqueId: 'abc-123-def');
        $variableResolver = new VariableResolver(new TxStore());
        $values = $variableResolver->resolve([['collection' => 'UNIQUE_ID']], $req);
        $this->assertCount(1, $values);
        $this->assertSame('abc-123-def', $values[0]->value);
    }

    public function testBodyProcessor(): void
    {
        $req = $this->req(bodyProcessor: 'JSON');
        $variableResolver = new VariableResolver(new TxStore());
        $values = $variableResolver->resolve([['collection' => 'REQBODY_PROCESSOR']], $req);
        $this->assertSame('JSON', $values[0]->value);
    }

    public function testFilesTmpNamesAndSizes(): void
    {
        $req = $this->req(files: [
            ['name' => 'upload', 'filename' => 'photo.jpg', 'tmp_name' => '/tmp/phpXYZ', 'size' => 1024],
        ]);
        $variableResolver = new VariableResolver(new TxStore());

        $tmp = $variableResolver->resolve([['collection' => 'FILES_TMPNAMES']], $req);
        $this->assertCount(1, $tmp);
        $this->assertSame('/tmp/phpXYZ', $tmp[0]->value);

        $sizes = $variableResolver->resolve([['collection' => 'FILES_SIZES']], $req);
        $this->assertSame('1024', $sizes[0]->value);
    }

    public function testFilesContentFromInline(): void
    {
        $req = $this->req(files: [
            ['name' => 'shell', 'filename' => 'x.php', 'content' => "<?php system(\$_GET['c']); ?>"],
        ]);
        $variableResolver = new VariableResolver(new TxStore());
        $values = $variableResolver->resolve([['collection' => 'FILES']], $req);
        $this->assertCount(1, $values);
        $this->assertStringContainsString('system(', $values[0]->value);
    }

    public function testMultipartFlagAndPartHeaders(): void
    {
        $req = $this->req(
            multipartFlags: ['MULTIPART_STRICT_ERROR' => 1, 'MULTIPART_BOUNDARY_QUOTED' => 1],
            multipartPartHeaders: ['Content-Disposition: form-data; name="x"'],
        );
        $variableResolver = new VariableResolver(new TxStore());

        $flag = $variableResolver->resolve([['collection' => 'MULTIPART_STRICT_ERROR']], $req);
        $this->assertSame('1', $flag[0]->value);

        $headers = $variableResolver->resolve([['collection' => 'MULTIPART_PART_HEADERS']], $req);
        $this->assertCount(1, $headers);
        $this->assertStringContainsString('Content-Disposition', $headers[0]->value);
    }

    public function testUnpopulatedOptionalTargetsReturnEmpty(): void
    {
        $req = $this->req();
        $variableResolver = new VariableResolver(new TxStore());

        $this->assertSame([], $variableResolver->resolve([['collection' => 'UNIQUE_ID']], $req));
        $this->assertSame([], $variableResolver->resolve([['collection' => 'REQBODY_PROCESSOR']], $req));
        $this->assertSame([], $variableResolver->resolve([['collection' => 'MULTIPART_STRICT_ERROR']], $req));
    }

    private function req(
        string $uri = '/',
        ?string $uniqueId = null,
        ?string $bodyProcessor = null,
        array $files = [],
        array $multipartFlags = [],
        array $multipartPartHeaders = [],
    ): RequestData {
        return new RequestData(
            method: 'GET',
            uri: $uri,
            rawUri: $uri,
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            files: $files,
            multipartFlags: $multipartFlags,
            multipartPartHeaders: $multipartPartHeaders,
            uniqueId: $uniqueId,
            bodyProcessor: $bodyProcessor,
        );
    }
}

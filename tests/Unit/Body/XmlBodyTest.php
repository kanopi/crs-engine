<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Body;

use Kanopi\Crs\Body\XmlBody;
use Kanopi\Crs\Request\RequestData;
use PHPUnit\Framework\TestCase;

final class XmlBodyTest extends TestCase
{
    public function testParsesValidXmlAndReturnsTextNodes(): void
    {
        $xmlBody = new XmlBody($this->req(
            body: '<order><item>shoes</item><item>shirt</item></order>',
            contentType: 'application/xml',
        ));
        $values = $xmlBody->xpath('/order/item');
        $this->assertSame(['shoes', 'shirt'], $values);
    }

    public function testWildcardXpathExtractsAllTextContent(): void
    {
        $xmlBody = new XmlBody($this->req(
            body: '<root><a>hello</a><b>world</b></root>',
            contentType: 'application/xml',
        ));
        $values = $xmlBody->xpath('/*');
        $this->assertNotEmpty($values);
        $this->assertStringContainsString('hello', $values[0]);
        $this->assertStringContainsString('world', $values[0]);
    }

    public function testIgnoresHtmlBodies(): void
    {
        $xmlBody = new XmlBody($this->req(
            body: '<html><body>hi</body></html>',
            contentType: 'text/html',
        ));
        $this->assertSame([], $xmlBody->xpath('/*'));
    }

    public function testRejectsMalformedXml(): void
    {
        $xmlBody = new XmlBody($this->req(
            body: '<unclosed>',
            contentType: 'application/xml',
        ));
        $this->assertSame([], $xmlBody->xpath('/*'));
    }

    public function testEmptyBodyReturnsEmpty(): void
    {
        $xmlBody = new XmlBody($this->req(body: '', contentType: 'application/xml'));
        $this->assertSame([], $xmlBody->xpath('/*'));
    }

    public function testXxeIsNotExpanded(): void
    {
        // A classic XXE payload — without entity-loader disabled this would
        // expand to /etc/hostname contents.
        $xml = <<<'XML'
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root>&xxe;</root>
XML;
        $xmlBody = new XmlBody($this->req(body: $xml, contentType: 'application/xml'));
        $values = $xmlBody->xpath('/root');
        $joined = trim(implode('', $values));
        // Whatever path libxml took, the resolved value must be empty —
        // either because the document was rejected, the entity wasn't
        // expanded, or the entity expanded to nothing. The one outcome
        // we won't accept is the hostname file leaking into $joined.
        $this->assertSame('', $joined, 'External entity must not expand');
    }

    public function testContentTypeWithoutXmlButBodyLooksLikeXmlStillParses(): void
    {
        $xmlBody = new XmlBody($this->req(
            body: '<note><msg>hi</msg></note>',
            contentType: 'application/octet-stream',
        ));
        $this->assertSame(['hi'], $xmlBody->xpath('/note/msg'));
    }

    private function req(string $body, string $contentType): RequestData
    {
        return new RequestData(
            method: 'POST',
            uri: '/api',
            rawUri: '/api',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            headers: ['Content-Type' => $contentType],
            body: $body,
        );
    }
}

<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Body;

use Kanopi\Crs\Body\XmlBody;
use Kanopi\Crs\Request\RequestData;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A WAF library must not leave libxml's process-global state mutated.
 *
 * XmlBody used to install a deny-everything external entity loader and never
 * put it back, so parsing one XML request body disabled external entity
 * resolution for the whole PHP process — breaking the host application's own
 * XSLT, DTD validation and SOAP work for the life of the worker.
 *
 * It no longer touches that global at all: XXE protection comes from omitting
 * LIBXML_NOENT, which these tests verify holds even against a permissive
 * host-installed loader. libxml_use_internal_errors() is still set, because it
 * is needed and can be restored honestly.
 */
final class XmlBodyGlobalStateTest extends TestCase
{
    private const XXE_BODY = '<?xml version="1.0"?><!DOCTYPE f [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><f>&xxe;</f>';

    private const EXTERNAL_DTD = '<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://example.invalid/x.dtd"><r/>';

    protected function tearDown(): void
    {
        libxml_set_external_entity_loader(null);
        libxml_clear_errors();
        libxml_use_internal_errors(false);
    }

    private function xmlRequest(string $body): RequestData
    {
        return new RequestData(
            method: 'POST',
            uri: '/',
            rawUri: '/',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            headers: ['Content-Type' => 'text/xml'],
            body: $body,
        );
    }

    /**
     * Parses a document with an external DTD reference, which makes libxml
     * call whatever entity loader is currently installed. Version-independent:
     * libxml_get_external_entity_loader() only exists from PHP 8.4.
     */
    private function loaderIsStillOurs(int &$counter): bool
    {
        $before = $counter;

        $domDocument = new \DOMDocument();
        libxml_use_internal_errors(true);
        @$domDocument->loadXML(self::EXTERNAL_DTD, LIBXML_DTDLOAD);
        libxml_clear_errors();
        libxml_use_internal_errors(false);

        return $counter > $before;
    }

    public function testHostEntityLoaderSurvivesAParse(): void
    {
        $calls = 0;
        libxml_set_external_entity_loader(static function () use (&$calls) {
            $calls++;
            return null;
        });

        (new XmlBody($this->xmlRequest('<?xml version="1.0"?><note><to>a</to></note>')))->document();

        $this->assertTrue(
            $this->loaderIsStillOurs($calls),
            "The engine replaced the host application's libxml entity loader and did not put it back.",
        );
    }

    public function testHostEntityLoaderSurvivesAMalformedBody(): void
    {
        $calls = 0;
        libxml_set_external_entity_loader(static function () use (&$calls) {
            $calls++;
            return null;
        });

        (new XmlBody($this->xmlRequest('<not xml at all <<<')))->document();

        $this->assertTrue($this->loaderIsStillOurs($calls), 'State must be restored on the failure path too.');
    }

    /**
     * @return iterable<string, array{0: bool}>
     */
    public static function internalErrorsProvider(): iterable
    {
        yield 'host had it off' => [false];
        yield 'host had it on'  => [true];
    }

    #[DataProvider('internalErrorsProvider')]
    public function testInternalErrorFlagIsRestored(bool $initial): void
    {
        libxml_use_internal_errors($initial);

        (new XmlBody($this->xmlRequest('<?xml version="1.0"?><note><to>a</to></note>')))->document();

        $this->assertSame($initial, libxml_use_internal_errors($initial));
    }

    public function testExternalEntitiesDoNotResolve(): void
    {
        $values = (new XmlBody($this->xmlRequest(self::XXE_BODY)))->xpath('//f');

        $this->assertStringNotContainsString(
            'localhost',
            implode("\n", $values),
            'XXE resolved — local file contents reached the rule engine.',
        );
    }

    /**
     * The load-bearing one. XXE protection here comes from omitting
     * LIBXML_NOENT, not from overriding the entity loader — so it has to hold
     * even when the host application has installed a loader that resolves
     * whatever it is handed. If anyone adds LIBXML_NOENT to
     * XmlBody::document(), this is the test that fails.
     */
    public function testExternalEntitiesDoNotResolveEvenWithAPermissiveHostLoader(): void
    {
        libxml_set_external_entity_loader(
            static fn (?string $publicId, ?string $systemId) => $systemId === null ? null : @fopen($systemId, 'r'),
        );

        $values = (new XmlBody($this->xmlRequest(self::XXE_BODY)))->xpath('//f');

        $this->assertStringNotContainsString(
            'localhost',
            implode("\n", $values),
            "XXE resolved through the host application's entity loader.",
        );
    }

    public function testValidXmlStillParses(): void
    {
        $xmlBody = new XmlBody($this->xmlRequest('<?xml version="1.0"?><note><to>Alice</to><to>Bob</to></note>'));

        $this->assertSame(['Alice', 'Bob'], $xmlBody->xpath('//to'));
    }
}

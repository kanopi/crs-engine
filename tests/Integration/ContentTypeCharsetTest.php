<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\CrsVerdict;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Runtime\CrsTxDefaults;
use PHPUnit\Framework\TestCase;

/**
 * Integration: the seeded allow-lists that CRS matches with @within have to
 * carry the same pipe delimiters the rules build into the needle.
 *
 * 920480 compares '|%{tx.1}|' against tx.allowed_request_content_type_charset.
 * Seeding that list as a bare pipe-separated string left the first and last
 * entries undelimited, so `|utf-8|` was not a substring of it and every
 * request declaring the most common charset on the web was blocked.
 */
final class ContentTypeCharsetTest extends TestCase
{
    private CrsEngine $crsEngine;

    protected function setUp(): void
    {
        $this->crsEngine = new CrsEngine(new CrsConfig(paranoia: 1));
    }

    /**
     * @return \Iterator<string, array{string}>
     */
    public static function allowedCharsetProvider(): \Iterator
    {
        yield 'utf-8' => ['utf-8'];
        yield 'iso-8859-1' => ['iso-8859-1'];
        yield 'iso-8859-15' => ['iso-8859-15'];
        yield 'windows-1252' => ['windows-1252'];
        yield 'uppercase utf-8' => ['UTF-8'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('allowedCharsetProvider')]
    public function testAllowedCharsetIsNotBlocked(string $charset): void
    {
        $crsVerdict = $this->verdict('application/x-www-form-urlencoded; charset=' . $charset);

        $this->assertFalse(
            $crsVerdict->isBlocked(),
            sprintf('charset=%s is on the allow-list and must not block.', $charset)
        );
        $this->assertNotContains(920480, array_column($crsVerdict->matchedRules, 'id'));
    }

    public function testDisallowedCharsetStillFires(): void
    {
        $crsVerdict = $this->verdict('application/x-www-form-urlencoded; charset=ibm037');

        $this->assertContains(
            920480,
            array_column($crsVerdict->matchedRules, 'id'),
            'A charset outside the allow-list should still be flagged by 920480.'
        );
    }

    public function testAllowedContentTypeIsNotBlocked(): void
    {
        foreach (['application/x-www-form-urlencoded', 'application/json', 'text/plain'] as $contentType) {
            $this->assertFalse(
                $this->verdict($contentType)->isBlocked(),
                $contentType . ' is on the allow-list and must not block.'
            );
        }
    }

    public function testEveryAllowListEntryIsPipeWrapped(): void
    {
        $defaults = CrsTxDefaults::forConfig(new CrsConfig());

        foreach (['tx.allowed_request_content_type', 'tx.allowed_request_content_type_charset'] as $key) {
            foreach (preg_split('/\s+/', trim($defaults[$key])) ?: [] as $entry) {
                $this->assertMatchesRegularExpression(
                    '/^\|[^|]+\|$/',
                    $entry,
                    sprintf('%s entry %s must be pipe-wrapped, or @within will not match it exactly.', $key, $entry)
                );
            }
        }
    }

    private function verdict(string $contentType): CrsVerdict
    {
        $body = 'name=Ada';

        return $this->crsEngine->evaluate(new RequestData(
            method: 'POST',
            uri: '/contact',
            rawUri: '/contact',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            postArgs: ['name' => 'Ada'],
            headers: [
                'host'           => 'example.test',
                'content-type'   => $contentType,
                'content-length' => (string) strlen($body),
            ],
            body: $body,
        ));
    }
}

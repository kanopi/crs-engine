<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\Parser\SecLangParser;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Runtime\CompiledRule;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

final class XssRulesTest extends TestCase
{
    private CrsEngine $crsEngine;

    protected function setUp(): void
    {
        $secLangParser = new SecLangParser();
        $parsed = $secLangParser->parseFile(__DIR__ . '/fixtures/REQUEST-941-APPLICATION-ATTACK-XSS.conf');

        $compiled = [];
        foreach ($parsed as $p) {
            $compiled[] = CompiledRule::fromArray($p->toArray());
        }

        $this->crsEngine = new CrsEngine(
            new CrsConfig(paranoia: 1),
            new RuleSet($compiled, 'fixture'),
        );
    }

    public function testBlocksScriptTag(): void
    {
        $crsVerdict = $this->crsEngine->evaluate($this->reqArg('comment', '<script>alert(1)</script>'));
        $this->assertTrue($crsVerdict->isBlocked());
    }

    public function testBlocksJavascriptUri(): void
    {
        $crsVerdict = $this->crsEngine->evaluate($this->reqArg('url', 'javascript:alert(1)'));
        $this->assertTrue($crsVerdict->isBlocked());
    }

    public function testBlocksHtmlEventHandler(): void
    {
        $crsVerdict = $this->crsEngine->evaluate($this->reqArg('html', '<img src=x onerror=alert(1)>'));
        $this->assertTrue($crsVerdict->isBlocked());
    }

    public function testAllowsBenignInput(): void
    {
        $crsVerdict = $this->crsEngine->evaluate($this->reqArg('comment', 'just a friendly hello'));
        $this->assertFalse($crsVerdict->isBlocked());
    }

    public function testHtmlEntityEncodedXssStillCaught(): void
    {
        $crsVerdict = $this->crsEngine->evaluate($this->reqArg('comment', '&lt;script&gt;alert(1)&lt;/script&gt;'));
        $this->assertTrue($crsVerdict->isBlocked(), 'HTML-entity-encoded <script> should match after t:htmlEntityDecode');
    }

    private function reqArg(string $name, string $value): RequestData
    {
        $qs = $name . '=' . urlencode($value);
        return new RequestData(
            method: 'GET',
            uri: '/?' . $qs,
            rawUri: '/?' . $qs,
            queryString: $qs,
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.5',
            queryArgs: [$name => $value],
        );
    }
}

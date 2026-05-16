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

/**
 * Integration: real CRS-shaped SQLi rules → engine → verdict.
 * Uses the bundled fixture so the test runs without network access.
 */
final class SqliRulesTest extends TestCase
{
    private CrsEngine $crsEngine;

    protected function setUp(): void
    {
        $secLangParser = new SecLangParser();
        $parsed = $secLangParser->parseFile(__DIR__ . '/fixtures/REQUEST-942-APPLICATION-ATTACK-SQLI.conf');

        $compiled = [];
        foreach ($parsed as $p) {
            $compiled[] = CompiledRule::fromArray($p->toArray());
        }

        $ruleSet = new RuleSet($compiled, 'fixture');

        $this->crsEngine = new CrsEngine(
            new CrsConfig(paranoia: 1),
            $ruleSet,
        );
    }

    public function testBlocksUnionSelectInQueryString(): void
    {
        $payload = "1 UNION SELECT password FROM users";
        $crsVerdict = $this->crsEngine->evaluate($this->requestWithArg('id', $payload));

        $this->assertTrue($crsVerdict->isBlocked(), 'UNION SELECT payload should block');
        $this->assertNotEmpty($crsVerdict->matchedRules);
        $this->assertContains('sqli', array_column($crsVerdict->matchedRules, 'category'));
    }

    public function testBlocksOrEqualsClassicTautology(): void
    {
        $payload = "' or 1=1";
        $crsVerdict = $this->crsEngine->evaluate($this->requestWithArg('login', $payload));
        $this->assertTrue($crsVerdict->isBlocked(), "Classic ' OR 1=1 tautology should block");
    }

    public function testBlocksDeleteFrom(): void
    {
        $crsVerdict = $this->crsEngine->evaluate($this->requestWithArg('q', 'DELETE FROM users'));
        $this->assertTrue($crsVerdict->isBlocked());
    }

    public function testAllowsBenignInput(): void
    {
        $crsVerdict = $this->crsEngine->evaluate($this->requestWithArg('q', 'hello world'));
        $this->assertFalse($crsVerdict->isBlocked(), 'Benign text must not block');
        $this->assertSame([], $crsVerdict->matchedRules);
    }

    public function testUrlEncodedPayloadStillCaught(): void
    {
        $encoded = rawurlencode("' or 1=1");
        $crsVerdict = $this->crsEngine->evaluate($this->requestWithArg('login', $encoded));
        $this->assertTrue($crsVerdict->isBlocked(), 'URL-encoded SQLi payload should still match after t:urlDecodeUni');
    }

    public function testMonitorModeDoesNotBlockButStillRecordsMatch(): void
    {
        $secLangParser = new SecLangParser();
        $parsed = $secLangParser->parseFile(__DIR__ . '/fixtures/REQUEST-942-APPLICATION-ATTACK-SQLI.conf');
        $compiled = [];
        foreach ($parsed as $p) {
            $compiled[] = CompiledRule::fromArray($p->toArray());
        }

        $crsEngine = new CrsEngine(
            new CrsConfig(paranoia: 1, mode: CrsConfig::MODE_MONITOR),
            new RuleSet($compiled, 'fixture'),
        );

        $crsVerdict = $crsEngine->evaluate($this->requestWithArg('login', "' or 1=1"));
        $this->assertFalse($crsVerdict->isBlocked());
        $this->assertNotEmpty($crsVerdict->matchedRules);
    }

    public function testDisabledRuleIsSkipped(): void
    {
        $secLangParser = new SecLangParser();
        $parsed = $secLangParser->parseFile(__DIR__ . '/fixtures/REQUEST-942-APPLICATION-ATTACK-SQLI.conf');
        $compiled = [];
        foreach ($parsed as $p) {
            $compiled[] = CompiledRule::fromArray($p->toArray());
        }

        $crsEngine = new CrsEngine(
            new CrsConfig(
                paranoia: 1,
                disabledRules: [942260, 942270, 942380],
            ),
            new RuleSet($compiled, 'fixture'),
        );

        $crsVerdict = $crsEngine->evaluate($this->requestWithArg('login', "' or 1=1"));
        $this->assertFalse($crsVerdict->isBlocked(), 'With all matching rules disabled, request should pass');
    }

    private function requestWithArg(string $name, string $value): RequestData
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

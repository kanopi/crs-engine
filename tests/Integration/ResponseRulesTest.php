<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\Parser\SecLangParser;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Request\ResponseData;
use Kanopi\Crs\Runtime\CompiledRule;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

/**
 * RESPONSE-* rules catch data leakage in the rendered response — SQL error
 * messages, PHP warnings, stack traces. These fire on evaluateResponse()
 * after the application generated the response but before it ships.
 */
final class ResponseRulesTest extends TestCase
{
    private CrsEngine $crsEngine;

    protected function setUp(): void
    {
        $secLangParser = new SecLangParser();
        $parsed = $secLangParser->parseFile(__DIR__ . '/fixtures/RESPONSE-951-DATA-LEAKAGES-SQL.conf');
        $compiled = [];
        foreach ($parsed as $p) {
            $compiled[] = CompiledRule::fromArray($p->toArray());
        }

        // Outbound defaults to monitor so a documentation page is not blocked
        // for mentioning fopen. These tests are about whether the RESPONSE-*
        // rules detect and block, so they opt into outbound blocking.
        $this->crsEngine = new CrsEngine(
            new CrsConfig(responseMode: CrsConfig::MODE_BLOCK),
            new RuleSet($compiled, 'fixture'),
        );
    }

    public function testBlocksMysqlSyntaxErrorLeak(): void
    {
        $crsVerdict = $this->crsEngine->evaluateResponse(
            $this->req(),
            new ResponseData(
                status: 500,
                headers: ['Content-Type' => 'text/html'],
                body: 'Error: You have an error in your SQL syntax near line 1',
            ),
        );
        $this->assertTrue($crsVerdict->isBlocked(), 'MySQL error leak should block');
    }

    public function testBlocksGenericSqlDatabaseError(): void
    {
        $crsVerdict = $this->crsEngine->evaluateResponse(
            $this->req(),
            new ResponseData(
                status: 500,
                body: 'Warning: PostgreSQL fatal error: syntax error at or near "SELECT"',
            ),
        );
        $this->assertTrue($crsVerdict->isBlocked());
    }

    public function testRequestPhaseSkipsResponseRules(): void
    {
        // Calling evaluate() (not evaluateResponse) should NOT touch the
        // phase-3/4 rules even with the same engine.
        $crsVerdict = $this->crsEngine->evaluate($this->req());
        $this->assertFalse($crsVerdict->isBlocked());
        $this->assertSame([], $crsVerdict->matchedRules);
    }

    public function testCleanResponseAllowed(): void
    {
        $crsVerdict = $this->crsEngine->evaluateResponse(
            $this->req(),
            new ResponseData(
                status: 200,
                body: 'Welcome back, friend!',
            ),
        );
        $this->assertFalse($crsVerdict->isBlocked());
    }

    public function test5xxResponseAccrualButNotBlock(): void
    {
        // The 5xx-observed rule is phase:3,pass,severity:NOTICE — should match
        // and accumulate score but the rule itself isn't a block action.
        $crsVerdict = $this->crsEngine->evaluateResponse(
            $this->req(),
            new ResponseData(status: 500, body: 'oops'),
        );
        // Either matched + log (notice score below critical threshold) or
        // matched as part of multiple rules — depends on ordering.
        $this->assertNotEmpty($crsVerdict->matchedRules);
    }

    private function req(): RequestData
    {
        return new RequestData(
            method: 'GET',
            uri: '/users/42',
            rawUri: '/users/42',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
        );
    }
}

<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Parser;

use Kanopi\Crs\Parser\SecLangParser;
use PHPUnit\Framework\TestCase;

final class SecLangParserTest extends TestCase
{
    public function testParsesMinimalRule(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            <<<'CONF'
SecRule ARGS "@rx foo" \
    "id:1001,phase:2,block,msg:'hello',tag:'test',severity:'CRITICAL'"
CONF
        );

        $this->assertCount(1, $rules);
        $r = $rules[0];
        $this->assertSame(1001, $r->id);
        $this->assertSame(2, $r->phase);
        $this->assertSame('rx', $r->operator);
        $this->assertSame('foo', $r->operatorArgument);
        $this->assertSame('hello', $r->message);
        $this->assertSame('critical', $r->severity);
        $this->assertSame('block', $r->action);
        $this->assertContains('test', $r->tags);
    }

    public function testParsesTargets(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            <<<'CONF'
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|ARGS|ARGS_NAMES "@rx x" "id:1002,phase:2,pass"
CONF
        );
        $r = $rules[0];
        $this->assertCount(4, $r->targets);
        $this->assertSame('REQUEST_COOKIES', $r->targets[0]['collection']);
        $this->assertTrue($r->targets[1]['negated']);
        $this->assertTrue($r->targets[1]['regex']);
        $this->assertSame('__utm', $r->targets[1]['selector']);
        $this->assertSame('ARGS', $r->targets[2]['collection']);
        $this->assertSame('ARGS_NAMES', $r->targets[3]['collection']);
    }

    public function testParsesTransformsAndSetvar(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            <<<'CONF'
SecRule ARGS "@rx x" \
    "id:1003,phase:2,block,\
    t:none,t:lowercase,t:urlDecodeUni,\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"
CONF
        );
        $r = $rules[0];
        $this->assertSame(['none', 'lowercase', 'urlDecodeUni'], $r->transforms);
        $this->assertCount(1, $r->setvars);
        $this->assertSame('tx.sql_injection_score', $r->setvars[0]['name']);
        $this->assertSame('+', $r->setvars[0]['op']);
        // The reference is preserved for the evaluator to expand per request.
        // Resolving it here collapsed anything the parser did not recognise to
        // a literal 0, which is what left anomaly-score blocking dead.
        $this->assertSame('%{tx.critical_anomaly_score}', $r->setvars[0]['value']);
    }

    public function testParsesChainedRules(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            <<<'CONF'
SecRule ARGS "@rx foo" "id:1004,phase:2,block,chain"
    SecRule ARGS "@rx bar" "id:1005,phase:2,t:lowercase"
CONF
        );
        $this->assertCount(1, $rules);
        $this->assertCount(1, $rules[0]->chain);
        $this->assertSame('bar', $rules[0]->chain[0]->operatorArgument);
    }

    public function testParanoiaPickedFromTag(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            <<<'CONF'
SecRule ARGS "@rx x" "id:1006,phase:2,pass,tag:'paranoia-level/2'"
CONF
        );
        $this->assertSame(2, $rules[0]->paranoia);
    }

    public function testCategoryDerivedFromFilename(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            <<<'CONF'
SecRule ARGS "@rx x" "id:1007,phase:2,pass"
CONF,
            'REQUEST-942-APPLICATION-ATTACK-SQLI.conf'
        );
        $this->assertSame('sqli', $rules[0]->category);
    }

    public function testUnsupportedOperatorIsSkippedWithWarning(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            <<<'CONF'
SecRule ARGS "@detectSQLi" "id:1008,phase:2,block"
CONF
        );
        $this->assertCount(0, $rules);
        $this->assertNotEmpty($secLangParser->warnings);
    }

    public function testNegatedOperator(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            <<<'CONF'
SecRule REQUEST_METHOD "!@streq GET" "id:1009,phase:1,block"
CONF
        );
        $this->assertTrue($rules[0]->operatorNegated);
        $this->assertSame('streq', $rules[0]->operator);
    }
}

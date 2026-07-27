<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Parser;

use Kanopi\Crs\Parser\SecLangParser;
use PHPUnit\Framework\TestCase;

/**
 * Regression cover for chain continuation parsing.
 *
 * A chain continuation carries no id of its own. The parser used to reject
 * every id-less SecRule, which dropped the real condition and left the chain
 * open — so the next unrelated rule was consumed as the chain child instead.
 * That lost the sibling from the top level and replaced the parent's qualifier
 * with something arbitrary.
 */
final class ChainContinuationTest extends TestCase
{
    public function testContinuationWithoutIdIsAttachedAndSiblingSurvives(): void
    {
        $conf = <<<'CONF'
        SecRule ARGS "@rx a" "id:10,phase:2,pass,chain"
            SecRule REQUEST_HEADERS:Content-Type "!@rx ^application/json"
        SecRule ARGS "@rx unrelated" "id:11,phase:2,pass"
        CONF;

        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString($conf, 'REQUEST-900-TEST.conf');

        $this->assertCount(2, $rules, 'The sibling rule must stay at the top level.');
        $this->assertSame(10, $rules[0]->id);
        $this->assertSame(11, $rules[1]->id);
        $this->assertSame([], $rules[1]->chain);

        $this->assertCount(1, $rules[0]->chain);
        $child = $rules[0]->chain[0];
        $this->assertSame('REQUEST_HEADERS', $child->targets[0]['collection']);
        $this->assertSame('Content-Type', $child->targets[0]['selector']);
        $this->assertTrue($child->operatorNegated);
        $this->assertSame([], $secLangParser->warnings);
    }

    public function testMultiLinkChainKeepsEveryCondition(): void
    {
        $conf = <<<'CONF'
        SecRule ARGS "@rx a" "id:20,phase:2,pass,chain"
            SecRule REQUEST_METHOD "@streq POST" "chain"
            SecRule REQUEST_HEADERS:Content-Type "@rx json"
        SecRule ARGS "@rx b" "id:21,phase:2,pass"
        CONF;

        $rules = (new SecLangParser())->parseString($conf, 'REQUEST-900-TEST.conf');

        $this->assertCount(2, $rules);
        $this->assertCount(2, $rules[0]->chain);
        $this->assertSame('REQUEST_METHOD', $rules[0]->chain[0]->targets[0]['collection']);
        $this->assertSame('REQUEST_HEADERS', $rules[0]->chain[1]->targets[0]['collection']);
        $this->assertSame(21, $rules[1]->id);
    }

    public function testContinuationInheritsNoIdOfItsOwn(): void
    {
        $conf = <<<'CONF'
        SecRule ARGS "@rx a" "id:30,phase:2,pass,chain"
            SecRule REQUEST_METHOD "@streq POST"
        CONF;

        $rules = (new SecLangParser())->parseString($conf, 'REQUEST-900-TEST.conf');

        $this->assertSame(0, $rules[0]->chain[0]->id, 'Chain children carry no CRS rule id.');
    }

    /**
     * Dropping the qualifier would leave the parent firing on the broader
     * condition alone, which turns a targeted rule into a false-positive
     * generator. Fail safe instead.
     */
    public function testUnsupportedOperatorInContinuationDropsTheWholeChain(): void
    {
        $conf = <<<'CONF'
        SecRule ARGS "@rx a" "id:40,phase:2,pass,chain"
            SecRule ARGS "@detectSQLi"
        SecRule ARGS "@rx b" "id:41,phase:2,pass"
        CONF;

        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString($conf, 'REQUEST-900-TEST.conf');

        $this->assertCount(1, $rules, 'Rule 40 must be dropped, not emitted without its qualifier.');
        $this->assertSame(41, $rules[0]->id);
        $this->assertContains(40, $secLangParser->skippedRules);
        $this->assertNotSame([], $secLangParser->warnings);
    }

    public function testChainStarterWithNoContinuationIsDropped(): void
    {
        $conf = <<<'CONF'
        SecRule ARGS "@rx a" "id:50,phase:2,pass,chain"
        SecMarker "END-FOO"
        CONF;

        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString($conf, 'REQUEST-900-TEST.conf');

        $this->assertCount(1, $rules);
        $this->assertSame('END-FOO', $rules[0]->marker);
        $this->assertContains(50, $secLangParser->skippedRules);
    }

    public function testChainStarterAtEndOfFileIsDropped(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            'SecRule ARGS "@rx a" "id:60,phase:2,pass,chain"',
            'REQUEST-900-TEST.conf',
        );

        $this->assertSame([], $rules);
        $this->assertContains(60, $secLangParser->skippedRules);
    }

    public function testTopLevelRuleWithoutIdIsStillRejectedAndWarned(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            'SecRule ARGS "@rx a" "phase:2,pass"',
            'REQUEST-900-TEST.conf',
        );

        $this->assertSame([], $rules);
        $this->assertNotSame([], $secLangParser->warnings);
    }

    public function testContinuationDeclaringAnIdIsWarnedButStillChained(): void
    {
        $conf = <<<'CONF'
        SecRule ARGS "@rx a" "id:70,phase:2,pass,chain"
            SecRule REQUEST_METHOD "@streq POST" "id:71,phase:2,pass"
        CONF;

        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString($conf, 'REQUEST-900-TEST.conf');

        $this->assertCount(1, $rules);
        $this->assertSame(70, $rules[0]->id);
        $this->assertCount(1, $rules[0]->chain);
        $this->assertStringContainsString('unexpectedly declares id', implode("\n", $secLangParser->warnings));
    }
}

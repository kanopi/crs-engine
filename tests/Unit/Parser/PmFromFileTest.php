<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Parser;

use Kanopi\Crs\Parser\SecLangParser;
use PHPUnit\Framework\TestCase;

final class PmFromFileTest extends TestCase
{
    public function testPmFromFileInlinesPhrasesAsPmf(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            <<<'CONF'
SecRule ARGS "@pmFromFile pm-test.data" "id:5001,phase:2,block,t:lowercase"
CONF,
            'fixture.conf',
            __DIR__ . '/../../Integration/fixtures',
        );

        $this->assertCount(1, $rules);
        $this->assertSame('pmf', $rules[0]->operator);
        $phrases = $rules[0]->operatorArgument;
        $this->assertStringContainsString('sleep', $phrases);
        $this->assertStringContainsString('benchmark', $phrases);
        $this->assertStringContainsString('load_file', $phrases);
        $this->assertStringContainsString('into outfile', $phrases);
    }

    public function testPmfAliasAlsoWorks(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            'SecRule ARGS "@pmf pm-test.data" "id:5002,phase:2,pass"',
            'fixture.conf',
            __DIR__ . '/../../Integration/fixtures',
        );
        $this->assertCount(1, $rules);
        $this->assertSame('pmf', $rules[0]->operator);
    }

    public function testMissingDataFileLeavesRuleUnsupported(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            'SecRule ARGS "@pmFromFile nonexistent.data" "id:5003,phase:2,pass"',
            'fixture.conf',
            __DIR__ . '/../../Integration/fixtures',
        );
        $this->assertCount(0, $rules);
        $this->assertNotEmpty($secLangParser->warnings);
    }

    public function testPmfPreservesMultiWordPhrases(): void
    {
        // Regression: previously we joined phrases with spaces which broke
        // multi-word phrases like "Mozilla/5.0 (compatible; Panoptic" —
        // splitting into bare "Mozilla/5.0" that matches any browser.
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            'SecRule REQUEST_HEADERS:User-Agent "@pmFromFile pm-test.data" "id:5004,phase:2,block,t:none"',
            'fixture.conf',
            __DIR__ . '/../../Integration/fixtures',
        );
        $this->assertCount(1, $rules);
        $arg = $rules[0]->operatorArgument;
        // Newlines should remain the separator inside the inlined argument.
        $this->assertStringContainsString("\n", $arg, 'pmf phrase list must be newline-separated');
    }
}

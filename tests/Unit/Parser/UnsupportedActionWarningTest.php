<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Parser;

use Kanopi\Crs\Parser\SecLangParser;
use PHPUnit\Framework\TestCase;

/**
 * Actions the engine recognises but does not implement have to be recorded.
 *
 * The rule still runs — these shape a detection rather than define it — but a
 * rule using one behaves differently here than under ModSecurity, and the
 * parser's warning channel is how that divergence stays visible across CRS
 * bumps. Dropping them in silence meant the refresh PR could report "4 parser
 * warnings (libinjection rules expected)" while a ctl:ruleRemoveById that
 * upstream relies on was being ignored.
 */
final class UnsupportedActionWarningTest extends TestCase
{
    /**
     * @return array<int, string>
     */
    private function warningsFor(string $conf): array
    {
        $secLangParser = new SecLangParser();
        $secLangParser->parseString($conf, 'REQUEST-920-PROTOCOL-ENFORCEMENT.conf');

        return $secLangParser->warnings;
    }

    /**
     * @return \Iterator<string, array{string}>
     */
    public static function consequentialActionProvider(): \Iterator
    {
        yield 'ctl' => ['ctl:ruleRemoveById=920540'];
        yield 'ctl body processor' => ['ctl:requestBodyProcessor=XML'];
        yield 'expirevar' => ["expirevar:'ip.block=600'"];
        yield 'deprecatevar' => ["deprecatevar:'ip.score=1/60'"];
        yield 'initcol' => ["initcol:'ip=%{remote_addr}'"];
        yield 'setsid' => ["setsid:'%{REQUEST_COOKIES.sid}'"];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('consequentialActionProvider')]
    public function testConsequentialActionIsWarnedAbout(string $action): void
    {
        $warnings = $this->warningsFor(
            sprintf('SecRule ARGS "@rx x" "id:920999,phase:2,pass,%s"', $action)
        );

        $this->assertCount(1, $warnings);
        $this->assertStringContainsString('rule 920999', $warnings[0]);
        $this->assertStringContainsString('unsupported action', $warnings[0]);
    }

    public function testTheWarningNamesTheActionAndItsValue(): void
    {
        $warnings = $this->warningsFor(
            'SecRule ARGS "@rx x" "id:920999,phase:2,pass,ctl:ruleRemoveById=920540"'
        );

        $this->assertStringContainsString('ctl:ruleRemoveById=920540', $warnings[0]);
    }

    public function testTheRuleItselfIsStillParsed(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            'SecRule ARGS "@rx attack" "id:920999,phase:2,block,ctl:ruleRemoveById=920540"',
            'REQUEST-920-PROTOCOL-ENFORCEMENT.conf'
        );

        $this->assertCount(1, $rules, 'An ignored action must not cost the whole detection.');
        $this->assertSame(920999, $rules[0]->id);
        $this->assertNotSame([], $secLangParser->warnings);
    }

    /**
     * @return \Iterator<string, array{string}>
     */
    public static function inertActionProvider(): \Iterator
    {
        yield 'ver' => ["ver:'OWASP_CRS/4.0.0'"];
        yield 'rev' => ["rev:'2'"];
        yield 'maturity' => ['maturity:9'];
        yield 'accuracy' => ['accuracy:9'];
        yield 'nolog' => ['nolog'];
        yield 'auditlog' => ['auditlog'];
        yield 'sanitiseArg' => ["sanitiseArg:'password'"];
    }

    /**
     * Warning on inert metadata would put a line on almost every CRS rule and
     * bury the handful that mean something.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('inertActionProvider')]
    public function testInertMetadataIsIgnoredSilently(string $action): void
    {
        $warnings = $this->warningsFor(
            sprintf('SecRule ARGS "@rx x" "id:920999,phase:2,pass,%s"', $action)
        );

        $this->assertSame([], $warnings);
    }

    public function testAnOrdinaryRuleProducesNoWarnings(): void
    {
        $this->assertSame([], $this->warningsFor(
            'SecRule ARGS "@rx attack" "id:920999,phase:2,block,t:none,t:lowercase,'
            . "msg:'test',tag:'attack-generic',severity:'CRITICAL',"
            . 'setvar:\'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}\'"'
        ));
    }

    public function testAChainContinuationIsNotReportedAsRuleZero(): void
    {
        $warnings = $this->warningsFor(
            "SecRule ARGS \"@rx x\" \"id:920999,phase:2,pass,chain\"\n"
            . '    SecRule REQUEST_METHOD "@streq POST" "ctl:forceRequestBodyVariable=On"'
        );

        $this->assertCount(1, $warnings);
        $this->assertStringContainsString('a chain continuation', $warnings[0]);
        $this->assertStringNotContainsString('rule 0', $warnings[0]);
    }

    public function testSecActionAlsoReportsUnsupportedActions(): void
    {
        $warnings = $this->warningsFor(
            'SecAction "id:900000,phase:1,pass,nolog,initcol:\'ip=%{remote_addr}\'"'
        );

        $this->assertCount(1, $warnings);
        $this->assertStringContainsString('rule 900000', $warnings[0]);
        $this->assertStringContainsString('initcol', $warnings[0]);
    }

    public function testSeveralUnsupportedActionsOnOneRuleAreEachReported(): void
    {
        $warnings = $this->warningsFor(
            'SecRule ARGS "@rx x" "id:920999,phase:2,pass,ctl:auditEngine=Off,initcol:\'ip=1\'"'
        );

        $this->assertCount(2, $warnings);
    }
}

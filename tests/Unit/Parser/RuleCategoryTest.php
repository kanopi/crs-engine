<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Parser;

use Kanopi\Crs\Parser\SecLangParser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Category assignment drives CrsConfig::$disabledCategories, so a wrong
 * category is a silent security downgrade: the operator disables one thing and
 * quietly turns off another.
 *
 * The old implementation matched words in the filename, which collided badly.
 * "rce" appears inside "enfoRCEment", so METHOD-ENFORCEMENT and
 * PROTOCOL-ENFORCEMENT were both filed as remote code execution — meaning
 * disabledCategories: ['rce'] silenced 132 rules across three unrelated
 * families. "php" and "java" matched the RESPONSE data-leakage files as well
 * as the REQUEST attack files.
 */
final class RuleCategoryTest extends TestCase
{
    private function categoryFor(string $filename): string
    {
        $rules = (new SecLangParser())->parseString(
            'SecRule ARGS "@rx x" "id:1,phase:2,pass"',
            $filename,
        );

        return $rules[0]->category;
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function crsFileProvider(): iterable
    {
        yield 'method enforcement'   => ['REQUEST-911-METHOD-ENFORCEMENT.conf', 'method_enforcement'];
        yield 'scanner detection'    => ['REQUEST-913-SCANNER-DETECTION.conf', 'scanner'];
        yield 'protocol enforcement' => ['REQUEST-920-PROTOCOL-ENFORCEMENT.conf', 'protocol_enforcement'];
        yield 'protocol attack'      => ['REQUEST-921-PROTOCOL-ATTACK.conf', 'protocol_attack'];
        yield 'multipart'            => ['REQUEST-922-MULTIPART-ATTACK.conf', 'multipart'];
        yield 'lfi'                  => ['REQUEST-930-APPLICATION-ATTACK-LFI.conf', 'lfi'];
        yield 'rfi'                  => ['REQUEST-931-APPLICATION-ATTACK-RFI.conf', 'rfi'];
        yield 'rce'                  => ['REQUEST-932-APPLICATION-ATTACK-RCE.conf', 'rce'];
        yield 'php'                  => ['REQUEST-933-APPLICATION-ATTACK-PHP.conf', 'php'];
        yield 'generic'              => ['REQUEST-934-APPLICATION-ATTACK-GENERIC.conf', 'generic'];
        yield 'xss'                  => ['REQUEST-941-APPLICATION-ATTACK-XSS.conf', 'xss'];
        yield 'sqli'                 => ['REQUEST-942-APPLICATION-ATTACK-SQLI.conf', 'sqli'];
        yield 'session fixation'     => ['REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf', 'session_fixation'];
        yield 'java'                 => ['REQUEST-944-APPLICATION-ATTACK-JAVA.conf', 'java'];
        yield 'supplemental sqli'    => ['REQUEST-948-TAUTOLOGY.conf', 'sqli'];
        yield 'inbound blocking'     => ['REQUEST-949-BLOCKING-EVALUATION.conf', 'blocking_evaluation'];
        yield 'response leak'        => ['RESPONSE-950-DATA-LEAKAGES.conf', 'response_leak'];
        yield 'response leak sql'    => ['RESPONSE-951-DATA-LEAKAGES-SQL.conf', 'response_leak_sql'];
        yield 'response leak java'   => ['RESPONSE-952-DATA-LEAKAGES-JAVA.conf', 'response_leak_java'];
        yield 'response leak php'    => ['RESPONSE-953-DATA-LEAKAGES-PHP.conf', 'response_leak_php'];
        yield 'response leak iis'    => ['RESPONSE-954-DATA-LEAKAGES-IIS.conf', 'response_leak_iis'];
        yield 'web shells'           => ['RESPONSE-955-WEB-SHELLS.conf', 'web_shell'];
        yield 'response leak ruby'   => ['RESPONSE-956-DATA-LEAKAGES-RUBY.conf', 'response_leak_ruby'];
        yield 'outbound blocking'    => ['RESPONSE-959-BLOCKING-EVALUATION.conf', 'blocking_evaluation'];
        yield 'correlation'          => ['RESPONSE-980-CORRELATION.conf', 'correlation'];
    }

    #[DataProvider('crsFileProvider')]
    public function testEveryShippedFileMapsToItsOwnCategory(string $filename, string $expected): void
    {
        $this->assertSame($expected, $this->categoryFor($filename));
    }

    /**
     * The specific collision behind #7: two different files that used to land
     * in the same bucket must not any more.
     */
    public function testRequestAndResponseAttackFilesDoNotShareACategory(): void
    {
        $this->assertNotSame(
            $this->categoryFor('REQUEST-933-APPLICATION-ATTACK-PHP.conf'),
            $this->categoryFor('RESPONSE-953-DATA-LEAKAGES-PHP.conf'),
        );

        $this->assertNotSame(
            $this->categoryFor('REQUEST-944-APPLICATION-ATTACK-JAVA.conf'),
            $this->categoryFor('RESPONSE-952-DATA-LEAKAGES-JAVA.conf'),
        );
    }

    /**
     * "enfoRCEment" contains "rce". This is the substring trap that made
     * disabling remote-code-execution rules also disable method and protocol
     * enforcement.
     */
    public function testEnforcementFilesAreNotFiledAsRemoteCodeExecution(): void
    {
        $this->assertSame('method_enforcement', $this->categoryFor('REQUEST-911-METHOD-ENFORCEMENT.conf'));
        $this->assertSame('protocol_enforcement', $this->categoryFor('REQUEST-920-PROTOCOL-ENFORCEMENT.conf'));
        $this->assertSame('rce', $this->categoryFor('REQUEST-932-APPLICATION-ATTACK-RCE.conf'));
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function unnumberedFileProvider(): iterable
    {
        yield 'leakage before attack type' => ['CUSTOM-DATA-LEAKAGES-PHP.conf', 'response_leak_php'];
        yield 'enforcement not rce'        => ['CUSTOM-PROTOCOL-ENFORCEMENT.conf', 'protocol_enforcement'];
        yield 'plain sqli'                 => ['CUSTOM-ATTACK-SQLI.conf', 'sqli'];
        yield 'unknown'                    => ['SOMETHING-ELSE.conf', 'misc'];
    }

    /**
     * A file CRS adds after this map was written, or a custom ruleset that
     * does not follow the numbering, still has to land somewhere sensible.
     */
    #[DataProvider('unnumberedFileProvider')]
    public function testKeywordFallbackIsOrderedCorrectly(string $filename, string $expected): void
    {
        $this->assertSame($expected, $this->categoryFor($filename));
    }
}

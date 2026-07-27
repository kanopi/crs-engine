<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Parser;

use Kanopi\Crs\Parser\SecLangParser;
use Kanopi\Crs\Transforms\TransformInterface;
use Kanopi\Crs\Transforms\TransformRegistry;
use PHPUnit\Framework\TestCase;

/**
 * A transform the engine does not implement is skipped at runtime, so the rule
 * matches against less-normalised input than its author assumed — precisely
 * what an anti-evasion transform exists to prevent.
 *
 * Nothing surfaced that before: TransformRegistry recorded unknown names into a
 * property no production code read, on an object CrsEngine rebuilt for every
 * evaluate() call. Reporting moved to parse time, where it lands in
 * manifest.json alongside the unsupported operators.
 */
final class UnknownTransformWarningTest extends TestCase
{
    /**
     * @return array<int, string>
     */
    private function warningsFor(string $conf, ?TransformRegistry $transformRegistry = null): array
    {
        $secLangParser = new SecLangParser($transformRegistry);
        $secLangParser->parseString($conf, 'REQUEST-941-APPLICATION-ATTACK-XSS.conf');

        return $secLangParser->warnings;
    }

    public function testUnknownTransformIsReported(): void
    {
        $warnings = $this->warningsFor(
            'SecRule ARGS "@rx x" "id:941999,phase:2,pass,t:none,t:jsDecode"'
        );

        $this->assertCount(1, $warnings);
        $this->assertStringContainsString('t:jsDecode', $warnings[0]);
        $this->assertStringContainsString('not implemented', $warnings[0]);
    }

    public function testKnownTransformsAreSilent(): void
    {
        $this->assertSame([], $this->warningsFor(
            'SecRule ARGS "@rx x" "id:941999,phase:2,pass,t:none,t:lowercase,t:urlDecodeUni,t:htmlEntityDecode"'
        ));
    }

    /**
     * `none` is a pipeline directive — it resets the chain — not a transform,
     * so it must not be reported as missing.
     */
    public function testNoneIsNotReportedAsUnknown(): void
    {
        $this->assertSame([], $this->warningsFor(
            'SecRule ARGS "@rx x" "id:941999,phase:2,pass,t:none"'
        ));
    }

    /**
     * CRS asks for six unimplemented transforms across 76 occurrences. One line
     * per occurrence would bury the six facts worth knowing.
     */
    public function testRepeatedUnknownTransformIsSummarisedNotRepeated(): void
    {
        $conf = '';
        for ($i = 0; $i < 5; $i++) {
            $conf .= sprintf("SecRule ARGS \"@rx x\" \"id:94100%d,phase:2,pass,t:jsDecode\"\n", $i);
        }

        $warnings = $this->warningsFor($conf);

        $this->assertCount(1, $warnings, 'One warning per transform per file, not per occurrence.');
        $this->assertStringContainsString('5 rules', $warnings[0]);
    }

    public function testSingularWordingForASingleRule(): void
    {
        $warnings = $this->warningsFor('SecRule ARGS "@rx x" "id:941999,phase:2,pass,t:cssDecode"');

        $this->assertStringContainsString('1 rule,', $warnings[0]);
    }

    public function testEachDistinctUnknownTransformGetsItsOwnLine(): void
    {
        $warnings = $this->warningsFor(
            'SecRule ARGS "@rx x" "id:941999,phase:2,pass,t:jsDecode,t:cssDecode,t:escapeSeqDecode"'
        );

        $this->assertCount(3, $warnings);
    }

    public function testTransformsInsideAChainAreCounted(): void
    {
        $warnings = $this->warningsFor(
            "SecRule ARGS \"@rx x\" \"id:941999,phase:2,pass,chain\"\n"
            . '    SecRule ARGS "@rx y" "t:jsDecode"'
        );

        $this->assertCount(1, $warnings);
        $this->assertStringContainsString('t:jsDecode', $warnings[0]);
    }

    /**
     * An integrator who has registered their own transform should not be told
     * it is missing.
     */
    public function testACustomRegisteredTransformIsNotReported(): void
    {
        $transformRegistry = new TransformRegistry();
        $transformRegistry->register(new class () implements TransformInterface {
            public function name(): string
            {
                return 'jsDecode';
            }

            public function apply(string $value): string
            {
                return $value;
            }
        });

        $this->assertSame([], $this->warningsFor(
            'SecRule ARGS "@rx x" "id:941999,phase:2,pass,t:jsDecode"',
            $transformRegistry
        ));
    }

    /**
     * The engine registers normalisePath, CRS only ever writes normalizePath,
     * and nothing connected the two — so the transform was dead code and 12
     * rules ran unnormalised. The warning is what makes that visible; wiring an
     * alias is deliberately not done here, because normalisePath also collapses
     * leading `../`, which would change what those rules see.
     */
    public function testTheNormalizePathSpellingGapIsReported(): void
    {
        $warnings = $this->warningsFor(
            'SecRule ARGS "@rx x" "id:930999,phase:2,pass,t:normalizePath"'
        );

        $this->assertCount(1, $warnings);
        $this->assertStringContainsString('t:normalizePath', $warnings[0]);
    }
}

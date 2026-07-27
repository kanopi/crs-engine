<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\Runtime\CompiledRule;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

/**
 * Invariants over the real bundled ruleset, not a fixture.
 *
 * These are the checks that would have caught the skipAfter and TX-resolution
 * defects: both left the engine reporting a healthy rule count while large
 * parts of the ruleset were unreachable. Run these after every CRS bump.
 */
final class RulesetInvariantsTest extends TestCase
{
    /** @var array<int, CompiledRule> */
    private static array $flat = [];

    public static function setUpBeforeClass(): void
    {
        $ruleSet = RuleSet::loadFromDirectory(dirname(__DIR__, 2) . '/rules', useCache: false);
        self::$flat = self::flatten($ruleSet->all());
    }

    /**
     * @param array<int, CompiledRule> $rules
     * @return array<int, CompiledRule>
     */
    private static function flatten(array $rules): array
    {
        $out = [];
        foreach ($rules as $rule) {
            $out[] = $rule;
            if ($rule->chain !== []) {
                $out = array_merge($out, self::flatten($rule->chain));
            }
        }

        return $out;
    }

    public function testEverySkipAfterTargetIsReachable(): void
    {
        $markers = [];
        $ids     = [];
        $tags    = [];
        foreach (self::$flat as $rule) {
            if ($rule->isMarker()) {
                $markers[$rule->marker] = true;
                continue;
            }

            $ids[(string) $rule->id] = true;
            foreach ($rule->tags as $tag) {
                $tags[$tag] = true;
            }
        }

        $unresolvable = [];
        foreach (self::$flat as $rule) {
            $target = $rule->skipAfter;
            if ($target === null) {
                continue;
            }

            if (isset($markers[$target]) || isset($ids[$target]) || isset($tags[$target])) {
                continue;
            }

            $unresolvable[$target] = true;
        }

        $this->assertSame(
            [],
            array_keys($unresolvable),
            'A skipAfter with no reachable landing point silently discards the rest of the ruleset.',
        );
    }

    public function testRulesetContainsMarkers(): void
    {
        $markers = array_filter(self::$flat, static fn (CompiledRule $r): bool => $r->isMarker());

        $this->assertNotEmpty(
            $markers,
            'CRS defines SecMarkers; none in the compiled ruleset means the parser dropped them again.',
        );
    }

    public function testMarkersCarryNoOperator(): void
    {
        foreach (self::$flat as $rule) {
            if (!$rule->isMarker()) {
                continue;
            }

            $this->assertSame('', $rule->operator, sprintf('Marker %s should not be evaluable.', (string) $rule->marker));
            $this->assertSame([], $rule->targets);
        }
    }

    /**
     * TX variables that no rule writes and CrsTxDefaults deliberately does not
     * seed yet. These are the crs-setup.conf / REQUEST-901-INITIALIZATION
     * values the engine replaces with CrsConfig.
     *
     * Seeding them is blocked on #16: the PL gate rules that read
     * detection_paranoia_level are currently mis-attached as chain children of
     * unrelated rules, so making them resolvable turns 954130 into a false
     * positive on any non-404 response. Seed these together with the #16 fix.
     *
     * @var array<int, string>
     */
    private const UNSEEDED_TX_VARS = [
        'DETECTION_PARANOIA_LEVEL',
        'BLOCKING_PARANOIA_LEVEL',
        'REPORTING_LEVEL',
        'DETECTION_ANOMALY_SCORE',
        'BLOCKING_ANOMALY_SCORE',
        'allow_method_override_parameter',
        'crs_skip_response_analysis',
    ];

    /**
     * Guards the read side of the setvar/TX contract: any TX variable a rule
     * reads should be one some rule can actually write. The allowlist above is
     * the known, documented exception set — if it grows, a rule has gone dark.
     */
    public function testTxTargetsCorrespondToWrittenVariables(): void
    {
        $written = [];
        foreach (self::$flat as $rule) {
            foreach ($rule->setvars as $setvar) {
                $name = strtolower($setvar['name']);
                $written[$name] = true;
                $written[preg_replace('/^tx\./', '', $name) ?? $name] = true;
            }
        }

        // Seeded by CrsTxDefaults rather than by any rule.
        foreach (\Kanopi\Crs\Runtime\CrsTxDefaults::forConfig(new \Kanopi\Crs\CrsConfig()) as $name => $_) {
            $name = strtolower($name);
            $written[$name] = true;
            $written[preg_replace('/^tx\./', '', $name) ?? $name] = true;
        }

        $unwritten = [];
        foreach (self::$flat as $rule) {
            foreach ($rule->targets as $target) {
                if (strtoupper($target['collection']) !== 'TX') {
                    continue;
                }

                $selector = $target['selector'] ?? null;
                // Regex selectors match a family of names, not one key.
                if ($selector === null || ($target['regex'] ?? false)) {
                    continue;
                }

                if (!isset($written[strtolower($selector)])) {
                    $unwritten[$selector] = true;
                }
            }
        }

        $unexpected = array_values(array_diff(array_keys($unwritten), self::UNSEEDED_TX_VARS));
        sort($unexpected);

        $this->assertSame(
            [],
            $unexpected,
            'These TX variables are read by a rule but never written or seeded, so those rules can never fire.',
        );
    }

    /**
     * The allowlist must shrink, not linger. Fails once a variable in it starts
     * being seeded, so the list cannot drift out of date silently.
     */
    public function testUnseededAllowlistIsStillAccurate(): void
    {
        $seeded = [];
        foreach (\Kanopi\Crs\Runtime\CrsTxDefaults::forConfig(new \Kanopi\Crs\CrsConfig()) as $name => $_) {
            $seeded[strtolower(preg_replace('/^tx\./', '', $name) ?? $name)] = true;
        }

        foreach (self::UNSEEDED_TX_VARS as $name) {
            $this->assertArrayNotHasKey(
                strtolower($name),
                $seeded,
                sprintf('%s is now seeded — drop it from UNSEEDED_TX_VARS.', $name),
            );
        }
    }
}

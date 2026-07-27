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
    /** @var array<int, CompiledRule> Top-level entries only (rules + markers). */
    private static array $top = [];

    /** @var array<int, CompiledRule> Top-level entries plus every chain child. */
    private static array $flat = [];

    public static function setUpBeforeClass(): void
    {
        $ruleSet = RuleSet::loadFromDirectory(dirname(__DIR__, 2) . '/rules', useCache: false);
        self::$top = $ruleSet->all();
        self::$flat = self::flatten(self::$top);
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

            if (isset($markers[$target])) {
                continue;
            }

            if (isset($ids[$target])) {
                continue;
            }

            if (isset($tags[$target])) {
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

    /**
     * A chain continuation has no id of its own. One that does means the
     * parser lost sync and consumed an unrelated sibling as the child — the
     * failure mode behind #16, which cost 51 rules and neutered 51 more.
     */
    public function testNoChainChildCarriesItsOwnRuleId(): void
    {
        $offenders = [];
        foreach (self::$flat as $rule) {
            foreach ($rule->chain as $child) {
                if ($child->id !== 0) {
                    $offenders[] = sprintf('%d swallowed %d', $rule->id, $child->id);
                }
            }
        }

        $this->assertSame([], $offenders, 'A chain child with a CRS rule id means an unrelated rule was consumed as a chain condition.');
    }

    /**
     * Guards against silent shrinkage: every upstream SecRule should end up
     * either at the top level or explicitly accounted for as skipped.
     */
    public function testTopLevelRuleCountMatchesUpstreamMinusSkipped(): void
    {
        $manifest = json_decode(
            (string) file_get_contents(dirname(__DIR__, 2) . '/rules/manifest.json'),
            true,
            flags: JSON_THROW_ON_ERROR,
        );

        $secRules     = 0;
        $secActions   = 0;
        $supplemental = 0;
        foreach (self::$top as $rule) {
            if ($rule->isMarker()) {
                continue;
            }

            if ($rule->isUnconditional()) {
                $secActions++;
                continue;
            }

            // Engine-owned rules from supplemental/, not part of CRS.
            if (in_array('kanopi-crs-engine', $rule->tags, true)) {
                $supplemental++;
                continue;
            }

            $secRules++;
        }

        // 587 upstream SecRule directives across the 24 parsed files, less the
        // 4 that use libinjection operators we do not implement.
        $this->assertSame(
            583,
            $secRules,
            sprintf(
                'Expected 583 CRS SecRules (587 upstream - 4 unsupported); manifest reports %s total entries. A shortfall means the parser is dropping or swallowing rules.',
                (string) ($manifest['rule_count'] ?? '?'),
            ),
        );

        $this->assertSame(1, $supplemental, 'supplemental/ should contribute exactly the 948100 tautology rule.');

        // The 6 SecAction directives are load-bearing: two reset the inbound
        // aggregate at the start of phase 2, two do the same for outbound, and
        // 980099/980170 roll the totals up for correlation.
        $this->assertSame(6, $secActions, 'Missing SecAction directives double-count per-paranoia-level scores across phases.');
    }

    public function testRulesetContainsMarkers(): void
    {
        $markers = array_filter(self::$flat, static fn (CompiledRule $compiledRule): bool => $compiledRule->isMarker());

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
     * TX variables a rule reads that no setvar writes and CrsTxDefaults does
     * not seed.
     *
     * The crs-setup values that used to live here are seeded as of #16, which
     * restored correct chain parsing and made that safe. What remains is
     * numeric: TX:0, TX:1, TX:2 are regex capture backreferences, populated by
     * the `capture` action rather than by setvar. Capture is parsed but never
     * applied at runtime — tracked in #8 — so these rules cannot fire yet.
     *
     * @var array<int, string>
     */
    private const UNSEEDED_TX_VARS = ['0', '1', '2'];

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
        foreach (array_keys(\Kanopi\Crs\Runtime\CrsTxDefaults::forConfig(new \Kanopi\Crs\CrsConfig())) as $name) {
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
                if ($selector === null) {
                    continue;
                }

                if ($target['regex'] ?? false) {
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
        foreach (array_keys(\Kanopi\Crs\Runtime\CrsTxDefaults::forConfig(new \Kanopi\Crs\CrsConfig())) as $name) {
            $seeded[strtolower(preg_replace('/^tx\./', '', $name) ?? $name)] = true;
        }

        $stale = [];
        foreach (self::UNSEEDED_TX_VARS as $name) {
            if (isset($seeded[strtolower($name)])) {
                $stale[] = $name;
            }
        }

        $this->assertSame([], $stale, 'Now seeded — drop from UNSEEDED_TX_VARS.');
    }
}

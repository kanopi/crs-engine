<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\Runtime\CompiledRule;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

/**
 * disabledCategories is a tuning knob operators reach for when a category is
 * noisy on their site. It has to disable exactly what it says.
 *
 * Because categories were derived by matching words in the CRS filename, they
 * collided: disabling `php` also silenced PHP response-leak detection, and
 * disabling `rce` also silenced method and protocol enforcement. An operator
 * turning off one noisy family was quietly turning off two others.
 */
final class DisabledCategoryScopeTest extends TestCase
{
    /** @var array<int, CompiledRule> */
    private static array $rules = [];

    public static function setUpBeforeClass(): void
    {
        self::$rules = RuleSet::loadFromDirectory(dirname(__DIR__, 2) . '/rules', useCache: false)->all();
    }

    /**
     * @param array<int, string> $disabled
     * @return array<string, int> category => rules still reachable
     */
    private function reachableByCategory(array $disabled): array
    {
        $crsConfig = new CrsConfig(paranoia: 4, disabledCategories: $disabled);

        $counts = [];
        foreach (self::$rules as $rule) {
            if ($rule->isMarker()) {
                continue;
            }

            if ($crsConfig->isCategoryDisabled($rule->category)) {
                continue;
            }

            $counts[$rule->category] = ($counts[$rule->category] ?? 0) + 1;
        }

        return $counts;
    }

    public function testDisablingPhpLeavesPhpResponseLeakDetectionActive(): void
    {
        $reachable = $this->reachableByCategory(['php']);

        $this->assertArrayNotHasKey('php', $reachable);
        $this->assertArrayHasKey(
            'response_leak_php',
            $reachable,
            'Disabling the PHP request-attack category also silenced PHP response-leak detection.',
        );
    }

    public function testDisablingJavaLeavesJavaResponseLeakDetectionActive(): void
    {
        $reachable = $this->reachableByCategory(['java']);

        $this->assertArrayNotHasKey('java', $reachable);
        $this->assertArrayHasKey('response_leak_java', $reachable);
    }

    public function testDisablingRceLeavesEnforcementRulesActive(): void
    {
        $reachable = $this->reachableByCategory(['rce']);

        $this->assertArrayNotHasKey('rce', $reachable);
        $this->assertArrayHasKey(
            'protocol_enforcement',
            $reachable,
            '"enfoRCEment" contains "rce" — disabling RCE also silenced protocol enforcement.',
        );
        $this->assertArrayHasKey('method_enforcement', $reachable);
    }

    public function testDisablingOneCategoryLeavesEveryOtherIntact(): void
    {
        $all = $this->reachableByCategory([]);
        unset($all['sqli']);

        $this->assertSame($all, $this->reachableByCategory(['sqli']));
    }

    /**
     * Attack categories describe one direction. Only the two genuinely
     * cross-phase concepts may span both, and they are named for it.
     */
    public function testNoAttackCategorySpansRequestAndResponsePhases(): void
    {
        $crossPhase = ['blocking_evaluation', 'correlation'];

        $phases = [];
        foreach (self::$rules as $rule) {
            if ($rule->isMarker()) {
                continue;
            }

            $phases[$rule->category][$rule->phase >= 3 ? 'response' : 'request'] = true;
        }

        $mixed = [];
        foreach ($phases as $category => $seen) {
            if (count($seen) > 1 && !in_array($category, $crossPhase, true)) {
                $mixed[] = $category;
            }
        }

        $this->assertSame([], $mixed, 'These categories cover both request and response rules, so disabling one does two things.');
    }

    /**
     * `misc` meant "the filename matcher did not recognise this file". Every
     * shipped file is now mapped explicitly, so nothing should land there.
     */
    public function testNoShippedRuleFallsBackToMisc(): void
    {
        $this->assertArrayNotHasKey('misc', $this->reachableByCategory([]));
    }
}

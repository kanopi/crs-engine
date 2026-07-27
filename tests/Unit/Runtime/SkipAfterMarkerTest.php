<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Runtime;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Runtime\CompiledRule;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

/**
 * Regression cover for skipAfter termination.
 *
 * Every skipAfter in CRS targets a SecMarker. The parser used to discard
 * markers, so a skip could never terminate and every rule after the skipping
 * rule was silently dropped for that request.
 */
final class SkipAfterMarkerTest extends TestCase
{
    /**
     * @param array<string, mixed> $overrides
     */
    private static function rule(int $id, array $overrides = []): CompiledRule
    {
        return CompiledRule::fromArray(array_merge([
            'id'           => $id,
            'phase'        => 2,
            'operator'     => 'rx',
            'operator_arg' => 'attack',
            'targets'      => [['collection' => 'ARGS']],
            'action'       => 'pass',
            'setvars'      => [['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '+', 'value' => '5']],
        ], $overrides));
    }

    private static function marker(string $name): CompiledRule
    {
        return CompiledRule::fromArray(['id' => 0, 'phase' => 0, 'marker' => $name]);
    }

    private static function request(string $value = 'attack'): RequestData
    {
        return new RequestData(
            method: 'GET',
            uri: '/',
            rawUri: '/',
            queryString: 'q=' . $value,
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            queryArgs: ['q' => $value],
        );
    }

    /**
     * @param array<int, CompiledRule> $rules
     * @return array<int, int>
     */
    private function matchedIds(array $rules): array
    {
        $engine = new CrsEngine(
            new CrsConfig(paranoia: 1, mode: CrsConfig::MODE_MONITOR),
            new RuleSet($rules, 'test'),
        );

        return array_column($engine->evaluate(self::request())->matchedRules, 'id');
    }

    public function testMarkerTerminatesTheSkip(): void
    {
        $matched = $this->matchedIds([
            self::rule(100, ['skip_after' => 'END-BLOCK']),
            self::rule(101),
            self::marker('END-BLOCK'),
            self::rule(102),
        ]);

        // 100 fires and skips to the marker; 101 is skipped; 102 must survive.
        $this->assertSame([100, 102], $matched);
    }

    public function testSkipSpansPhasesWithinTheSameRun(): void
    {
        // A phase-1 rule starting a skip must still land on the marker even
        // though the marker itself carries no phase.
        $matched = $this->matchedIds([
            self::rule(200, ['phase' => 1, 'skip_after' => 'END-BLOCK']),
            self::rule(201, ['phase' => 1]),
            self::rule(202, ['phase' => 2]),
            self::marker('END-BLOCK'),
            self::rule(203, ['phase' => 2]),
        ]);

        $this->assertSame([200, 203], $matched);
    }

    public function testNonMatchingRuleDoesNotStartASkip(): void
    {
        $matched = $this->matchedIds([
            self::rule(300, ['operator_arg' => 'no-such-payload', 'skip_after' => 'END-BLOCK']),
            self::rule(301),
            self::marker('END-BLOCK'),
            self::rule(302),
        ]);

        $this->assertSame([301, 302], $matched);
    }

    public function testUnrelatedMarkerDoesNotTerminateTheSkip(): void
    {
        $matched = $this->matchedIds([
            self::rule(400, ['skip_after' => 'END-BLOCK']),
            self::marker('SOME-OTHER-MARKER'),
            self::rule(401),
            self::marker('END-BLOCK'),
            self::rule(402),
        ]);

        $this->assertSame([400, 402], $matched);
    }

    public function testMarkersAreNeverEvaluatedAsRules(): void
    {
        $matched = $this->matchedIds([
            self::marker('LEADING-MARKER'),
            self::rule(500),
        ]);

        $this->assertSame([500], $matched);
    }

    public function testSkipAfterStillResolvesByRuleId(): void
    {
        // The pre-existing id/tag fallback must keep working.
        $matched = $this->matchedIds([
            self::rule(600, ['skip_after' => '602']),
            self::rule(601),
            self::rule(602),
            self::rule(603),
        ]);

        $this->assertSame([600, 603], $matched);
    }
}

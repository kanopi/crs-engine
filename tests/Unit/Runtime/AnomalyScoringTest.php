<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Runtime;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\CrsVerdict;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Request\ResponseData;
use Kanopi\Crs\Runtime\CompiledRule;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

/**
 * Regression cover for the anomaly-scoring pipeline.
 *
 * Four defects made CrsConfig::$anomalyThresholds inert:
 *   - `block` was treated as disruptive, so the first matching detection rule
 *     short-circuited and no score ever accumulated
 *   - setvar right-hand sides were resolved at parse time, collapsing
 *     %{tx.inbound_anomaly_score_pl1} to a literal 0
 *   - SecAction was skipped, so the phase-2 reset never ran and per-paranoia
 *     level scores were counted twice
 *   - the outbound total was never read back
 */
final class AnomalyScoringTest extends TestCase
{
    /**
     * @param array<string, mixed> $overrides
     */
    private function rule(int $id, array $overrides = []): CompiledRule
    {
        return CompiledRule::fromArray(array_merge([
            'id'           => $id,
            'phase'        => 2,
            'operator'     => 'rx',
            'operator_arg' => 'attack',
            'targets'      => [['collection' => 'ARGS']],
            'action'       => 'block',
            'message'      => 'test detection ' . $id,
            'setvars'      => [['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '+', 'value' => '5']],
        ], $overrides));
    }

    private function request(string $value = 'attack'): RequestData
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
     */
    private function engine(array $rules, int $threshold = 5, string $mode = CrsConfig::MODE_BLOCK): CrsEngine
    {
        return new CrsEngine(
            new CrsConfig(
                paranoia: 1,
                mode: $mode,
                anomalyThresholds: ['inbound' => $threshold, 'outbound' => $threshold],
            ),
            new RuleSet($rules, 'test'),
        );
    }

    public function testBlockActionIsNotDisruptiveAndScoresAccumulate(): void
    {
        // Three `block` rules at 5 each. If `block` short-circuited, only the
        // first would run and the total would be 5.
        $crsVerdict = $this->engine([$this->rule(1), $this->rule(2), $this->rule(3)], threshold: 100)
            ->evaluate($this->request());

        $this->assertSame(15, $crsVerdict->totalScore);
        $this->assertCount(3, $crsVerdict->matchedRules);
        $this->assertNull($crsVerdict->blockingRuleId);
    }

    public function testDenyActionIsStillDisruptive(): void
    {
        $crsVerdict = $this->engine([
            $this->rule(1, ['action' => 'deny']),
            $this->rule(2),
        ], threshold: 100)->evaluate($this->request());

        $this->assertTrue($crsVerdict->isBlocked());
        $this->assertSame(1, $crsVerdict->blockingRuleId);
        $this->assertCount(1, $crsVerdict->matchedRules, 'Evaluation should stop at the disruptive rule.');
    }

    public function testDenyIsNotDisruptiveInMonitorMode(): void
    {
        $crsVerdict = $this->engine([
            $this->rule(1, ['action' => 'deny']),
            $this->rule(2),
        ], threshold: 100, mode: CrsConfig::MODE_MONITOR)->evaluate($this->request());

        $this->assertFalse($crsVerdict->isBlocked());
        $this->assertCount(2, $crsVerdict->matchedRules);
    }

    public function testThresholdDecidesTheVerdict(): void
    {
        $rules = [$this->rule(1), $this->rule(2)];  // 10 total

        $this->assertSame(CrsVerdict::ACTION_BLOCK, $this->engine($rules, threshold: 10)->evaluate($this->request())->action);
        $this->assertSame(CrsVerdict::ACTION_LOG, $this->engine($rules, threshold: 11)->evaluate($this->request())->action);
    }

    public function testSetvarReferencesAreExpandedAtRuntime(): void
    {
        // tx.critical_anomaly_score is seeded to 5 by CrsTxDefaults. Resolving
        // this at parse time is what produced literal zeros.
        $crsVerdict = $this->engine([
            $this->rule(1, ['setvars' => [
                ['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '+', 'value' => '%{tx.critical_anomaly_score}'],
            ]]),
        ], threshold: 100)->evaluate($this->request());

        $this->assertSame(5, $crsVerdict->totalScore);
        $this->assertSame(5, $crsVerdict->matchedRules[0]['score']);
    }

    public function testUnresolvableReferenceDoesNotCrash(): void
    {
        $crsVerdict = $this->engine([
            $this->rule(1, ['setvars' => [
                ['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '+', 'value' => '%{tx.no_such_variable}'],
            ]]),
        ], threshold: 100)->evaluate($this->request());

        $this->assertSame(0, $crsVerdict->totalScore);
    }

    public function testSecActionAppliesUnconditionallyAndCanResetTheAggregate(): void
    {
        $compiledRule = CompiledRule::fromArray([
            'id'            => 99,
            'phase'         => 2,
            'unconditional' => true,
            'setvars'       => [['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '=', 'value' => '0']],
        ]);

        // Rule 1 scores 5, the SecAction zeroes the bucket, rule 2 scores 5.
        $crsVerdict = $this->engine([$this->rule(1), $compiledRule, $this->rule(2)], threshold: 100)
            ->evaluate($this->request());

        $this->assertSame(5, $crsVerdict->totalScore, "The SecAction reset should have discarded the first rule's score.");
    }

    public function testSecActionIsNotReportedAsAMatchedRule(): void
    {
        $compiledRule = CompiledRule::fromArray([
            'id'            => 99,
            'phase'         => 2,
            'unconditional' => true,
            'setvars'       => [['name' => 'tx.something', 'op' => '=', 'value' => '1']],
        ]);

        $crsVerdict = $this->engine([$compiledRule, $this->rule(1)], threshold: 100)->evaluate($this->request());

        $this->assertSame([1], array_column($crsVerdict->matchedRules, 'id'));
    }

    /**
     * CRS rules bump two counters with the same value — the category counter
     * and the anomaly bucket. Summing both reported double the contribution.
     */
    public function testPerRuleScoreCountsTheAnomalyBucketOnly(): void
    {
        $crsVerdict = $this->engine([
            $this->rule(1, ['setvars' => [
                ['name' => 'tx.sql_injection_score', 'op' => '+', 'value' => '5'],
                ['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '+', 'value' => '5'],
            ]]),
        ], threshold: 100)->evaluate($this->request());

        $this->assertSame(5, $crsVerdict->matchedRules[0]['score']);
        $this->assertSame(5, $crsVerdict->totalScore);
    }

    public function testCategoryScoresExcludeEngineAccumulators(): void
    {
        $crsVerdict = $this->engine([
            $this->rule(1, ['setvars' => [
                ['name' => 'tx.sql_injection_score', 'op' => '+', 'value' => '5'],
                ['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '+', 'value' => '5'],
            ]]),
        ], threshold: 100)->evaluate($this->request());

        $this->assertSame(['sql_injection' => 5], $crsVerdict->scores);
    }

    public function testControlFlowRulesAreNotReported(): void
    {
        // No message and no anomaly contribution: a paranoia gate or skip rule.
        $crsVerdict = $this->engine([
            $this->rule(1, ['message' => '', 'setvars' => []]),
            $this->rule(2),
        ], threshold: 100)->evaluate($this->request());

        $this->assertSame([2], array_column($crsVerdict->matchedRules, 'id'));
    }

    public function testOutboundScoreIsCountedAndUsesTheOutboundThreshold(): void
    {
        $compiledRule = CompiledRule::fromArray([
            'id'           => 500,
            'phase'        => 4,
            'operator'     => 'rx',
            'operator_arg' => 'SQL syntax',
            'targets'      => [['collection' => 'RESPONSE_BODY']],
            'action'       => 'block',
            'message'      => 'sql leak',
            'setvars'      => [['name' => 'tx.outbound_anomaly_score_pl1', 'op' => '+', 'value' => '5']],
        ]);

        $crsVerdict = $this->engine([$compiledRule], threshold: 5)->evaluateResponse(
            $this->request('x'),
            new ResponseData(status: 200, headers: ['Content-Type' => 'text/html'], body: 'You have an error in your SQL syntax'),
        );

        $this->assertSame(5, $crsVerdict->totalScore);
        $this->assertTrue($crsVerdict->isBlocked());
    }

    public function testInboundScoreDoesNotLeakIntoTheOutboundTotal(): void
    {
        $crsVerdict = $this->engine([
            $this->rule(1),  // phase 2, inbound
            CompiledRule::fromArray([
                'id' => 500, 'phase' => 4, 'operator' => 'rx', 'operator_arg' => '.*',
                'targets' => [['collection' => 'RESPONSE_BODY']], 'message' => 'noop', 'setvars' => [],
            ]),
        ], threshold: 100)->evaluateResponse(
            $this->request(),
            new ResponseData(status: 200, body: 'clean'),
        );

        $this->assertSame(0, $crsVerdict->totalScore, 'Request-phase score must not be counted in the response verdict.');
    }
}

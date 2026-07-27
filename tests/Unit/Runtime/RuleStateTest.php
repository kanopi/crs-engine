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
 * Rule state that the parser recorded and the evaluator ignored.
 *
 * `capture` was set on 272 rules and never read, so every %{TX.0} reference
 * expanded to an empty string. setvar *names* were used verbatim, so CRS's
 * per-parameter counters — setvar:'tx.paramcounter_%{MATCHED_VAR_NAME}=+1' —
 * all collapsed onto one literal key. TX regex selectors were ignored, so the
 * rules that read those counters back could never fire. And chain children's
 * setvars were never applied at all, which meant all 51 chained rules
 * contributed zero anomaly score.
 */
final class RuleStateTest extends TestCase
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
            'action'       => 'pass',
            'message'      => 'rule ' . $id,
        ], $overrides));
    }

    /**
     * @param array<int, CompiledRule> $rules
     * @param array<string, string> $args
     */
    private function evaluate(array $rules, array $args = ['q' => 'attack']): \Kanopi\Crs\CrsVerdict
    {
        $crsEngine = new CrsEngine(
            new CrsConfig(paranoia: 1, mode: CrsConfig::MODE_MONITOR, anomalyThresholds: ['inbound' => 1000]),
            new RuleSet($rules, 'test'),
        );

        return $crsEngine->evaluate(new RequestData(
            method: 'GET',
            uri: '/',
            rawUri: '/',
            queryString: http_build_query($args),
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            queryArgs: $args,
        ));
    }

    // ------------------------------------------------------------- capture

    /**
     * Captures a number and spends it as the anomaly score, so the assertion
     * can only pass if group 1 really reached the TX store.
     */
    public function testCaptureGroupsBecomeReadableAsTxVariables(): void
    {
        $crsVerdict = $this->evaluate([
            $this->rule(1, [
                'operator_arg' => 'id-(\d+)',
                'capture'      => true,
                'setvars'      => [
                    ['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '+', 'value' => '%{tx.1}'],
                ],
            ]),
        ], ['q' => 'id-7']);

        $this->assertSame(7, $crsVerdict->totalScore, 'Capture group 1 was not written to TX:1.');
    }

    public function testCaptureGroupZeroIsTheWholeMatch(): void
    {
        $crsVerdict = $this->evaluate([
            $this->rule(1, [
                'operator_arg' => '\d+',
                'capture'      => true,
                'logdata'      => 'group0=%{tx.0}',
            ]),
        ], ['q' => 'id-42']);

        $this->assertSame('group0=42', $crsVerdict->matchedRules[0]['logdata']);
    }

    public function testCaptureIsReadableByAChainedCondition(): void
    {
        $compiledRule = $this->rule(10, [
            'operator_arg' => 'id-(\d+)',
            'capture'      => true,
            'chain'        => [[
                'id'           => 0,
                'phase'        => 2,
                'operator'     => 'eq',
                'operator_arg' => '%{tx.1}',
                'targets'      => [['collection' => 'TX', 'selector' => '1']],
                'setvars'      => [['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '+', 'value' => '5']],
            ]],
        ]);

        $crsVerdict = $this->evaluate([$compiledRule], ['q' => 'id-42']);

        $this->assertSame([10], array_column($crsVerdict->matchedRules, 'id'), "A chained condition could not read the starter's capture.");
        $this->assertSame(5, $crsVerdict->totalScore);
    }

    public function testCapturesAreNotWrittenWithoutTheCaptureAction(): void
    {
        $crsVerdict = $this->evaluate([
            $this->rule(1, ['operator_arg' => 'att(ack)']),
            $this->rule(2, [
                'operator_arg' => '.*',
                'targets'      => [['collection' => 'TX', 'selector' => '1']],
                'message'      => 'read tx.1',
            ]),
        ]);

        $this->assertSame([1], array_column($crsVerdict->matchedRules, 'id'));
    }

    // ------------------------------------------------- setvar name expansion

    /**
     * The selector matches only the *resolved* key, so this fails if the name
     * is stored with a literal `%{MATCHED_VAR_NAME}` in it.
     */
    public function testSetvarNamesExpandMatchedVarName(): void
    {
        $crsVerdict = $this->evaluate([
            $this->rule(1, ['setvars' => [
                ['name' => 'tx.counter_%{MATCHED_VAR_NAME}', 'op' => '+', 'value' => '1'],
            ]]),
            $this->rule(2, [
                'operator'     => 'eq',
                'operator_arg' => '1',
                'targets'      => [['collection' => 'TX', 'selector' => '^counter_args:q$', 'regex' => true]],
                'message'      => 'counter under its resolved name',
                'setvars'      => [['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '+', 'value' => '5']],
            ]),
        ]);

        $this->assertSame([1, 2], array_column($crsVerdict->matchedRules, 'id'));
        $this->assertSame(5, $crsVerdict->totalScore, 'The setvar name kept its literal %{MATCHED_VAR_NAME} placeholder.');
    }

    public function testUnexpandedPlaceholderKeyIsNotCreated(): void
    {
        $crsVerdict = $this->evaluate([
            $this->rule(1, ['setvars' => [
                ['name' => 'tx.counter_%{MATCHED_VAR_NAME}', 'op' => '+', 'value' => '1'],
            ]]),
            $this->rule(2, [
                'operator'     => 'rx',
                'operator_arg' => '.*',
                'targets'      => [['collection' => 'TX', 'selector' => 'counter_%\{', 'regex' => true]],
                'message'      => 'literal placeholder key exists',
            ]),
        ]);

        $this->assertSame([1], array_column($crsVerdict->matchedRules, 'id'));
    }

    public function testSetvarNamesExpandMatchedVarNamePerTarget(): void
    {
        $crsVerdict = $this->evaluate([
            $this->rule(1, [
                'targets' => [['collection' => 'ARGS', 'selector' => 'b']],
                'setvars' => [['name' => 'tx.counter_%{MATCHED_VAR_NAME}', 'op' => '+', 'value' => '1']],
            ]),
            $this->rule(2, [
                'operator'     => 'eq',
                'operator_arg' => '1',
                'targets'      => [['collection' => 'TX', 'selector' => '^counter_args:b$', 'regex' => true]],
                'message'      => 'named for the parameter that matched',
            ]),
        ], ['a' => 'clean', 'b' => 'attack']);

        $this->assertSame([1, 2], array_column($crsVerdict->matchedRules, 'id'));
    }

    // ---------------------------------------------------- TX regex selectors

    public function testTxRegexSelectorMatchesAFamilyOfNames(): void
    {
        $crsVerdict = $this->evaluate([
            $this->rule(1, ['setvars' => [
                ['name' => 'tx.family_alpha', 'op' => '=', 'value' => 'x'],
                ['name' => 'tx.family_beta', 'op' => '=', 'value' => 'x'],
                ['name' => 'tx.unrelated', 'op' => '=', 'value' => 'x'],
            ]]),
            $this->rule(2, [
                'operator'     => 'streq',
                'operator_arg' => 'x',
                'targets'      => [['collection' => 'TX', 'selector' => 'family_.*', 'regex' => true]],
                'message'      => 'family matched',
            ]),
        ]);

        $this->assertSame([1, 2], array_column($crsVerdict->matchedRules, 'id'));
    }

    public function testExactTxSelectorIsNotTreatedAsARegex(): void
    {
        $crsVerdict = $this->evaluate([
            $this->rule(1, ['setvars' => [['name' => 'tx.family_alpha', 'op' => '=', 'value' => 'x']]]),
            $this->rule(2, [
                'operator'     => 'streq',
                'operator_arg' => 'x',
                'targets'      => [['collection' => 'TX', 'selector' => 'family_.*']],
                'message'      => 'should not match',
            ]),
        ]);

        $this->assertSame([1], array_column($crsVerdict->matchedRules, 'id'));
    }

    // ------------------------------------------------------- chain setvars

    public function testChainChildSetvarsAreApplied(): void
    {
        $crsVerdict = $this->evaluate([
            $this->rule(20, [
                'chain' => [[
                    'id'           => 0,
                    'phase'        => 2,
                    'operator'     => 'rx',
                    'operator_arg' => '.*',
                    'targets'      => [['collection' => 'ARGS']],
                    'setvars'      => [['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '+', 'value' => '5']],
                ]],
            ]),
        ]);

        $this->assertSame(5, $crsVerdict->totalScore, 'A chained rule contributed no anomaly score.');
        $this->assertSame(5, $crsVerdict->matchedRules[0]['score']);
    }

    public function testChainThatDoesNotMatchIsNotReported(): void
    {
        $crsVerdict = $this->evaluate([
            $this->rule(20, [
                'chain' => [[
                    'id'           => 0,
                    'phase'        => 2,
                    'operator'     => 'rx',
                    'operator_arg' => 'never-present',
                    'targets'      => [['collection' => 'ARGS']],
                    'setvars'      => [['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '+', 'value' => '5']],
                ]],
            ]),
        ]);

        $this->assertSame([], $crsVerdict->matchedRules);
        $this->assertSame(0, $crsVerdict->totalScore);
    }

    // ------------------------------------------------------------- logdata

    public function testLogdataIsExpandedAndSurfacedOnTheVerdict(): void
    {
        $crsVerdict = $this->evaluate([
            $this->rule(1, ['logdata' => 'Matched %{MATCHED_VAR} in %{MATCHED_VAR_NAME}']),
        ]);

        $this->assertSame('Matched attack in ARGS:q', $crsVerdict->matchedRules[0]['logdata']);
    }

    public function testLogdataIsNullWhenTheRuleDoesNotDefineIt(): void
    {
        $crsVerdict = $this->evaluate([$this->rule(1)]);

        $this->assertNull($crsVerdict->matchedRules[0]['logdata']);
    }
}

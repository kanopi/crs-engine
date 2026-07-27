<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Runtime;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\CrsVerdict;
use Kanopi\Crs\Operators\OperatorInterface;
use Kanopi\Crs\Operators\OperatorMatch;
use Kanopi\Crs\Operators\OperatorRegistry;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Runtime\CompiledRule;
use Kanopi\Crs\Runtime\RuleSet;
use Kanopi\Crs\Tests\Support\ErrorsOnFirstCallOperator;
use Kanopi\Crs\Tests\Support\FaultyOperator;
use Kanopi\Crs\Tests\Support\NeverMatchesOperator;
use PHPUnit\Framework\TestCase;

/**
 * How the evaluator treats an operator that could not decide. Driven through a
 * stub operator rather than a real PCRE failure, so the behaviour under test is
 * the evaluator's and not PCRE's.
 */
final class OperatorErrorHandlingTest extends TestCase
{
    private function registryWith(OperatorInterface $operator): OperatorRegistry
    {
        $operatorRegistry = new OperatorRegistry();
        $operatorRegistry->register($operator);

        return $operatorRegistry;
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function ruleSet(array $overrides = []): RuleSet
    {
        return new RuleSet([CompiledRule::fromArray([
            'id'       => 942999,
            'phase'    => 2,
            'operator' => 'faulty',
            'targets'  => [['collection' => 'ARGS']],
            'action'   => 'pass',
            'severity' => 'critical',
            'message'  => 'stub',
            'category' => 'sqli',
            ...$overrides,
        ])], 'stub');
    }

    private function request(): RequestData
    {
        return new RequestData(
            method: 'GET',
            uri: '/',
            rawUri: '/',
            queryString: 'q=x',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            queryArgs: ['q' => 'x'],
        );
    }

    private function evaluate(RuleSet $ruleSet, OperatorInterface $operator, ?CrsConfig $crsConfig = null): CrsVerdict
    {
        return (new CrsEngine(
            $crsConfig ?? new CrsConfig(paranoia: 1),
            $ruleSet,
            $this->registryWith($operator),
        ))->evaluate($this->request());
    }

    public function testErrorIsRecordedOnTheVerdict(): void
    {
        $crsVerdict = $this->evaluate($this->ruleSet(), new FaultyOperator());

        $this->assertTrue($crsVerdict->hasOperatorErrors());
        $this->assertSame(
            [['rule_id' => 942999, 'operator' => 'faulty', 'error' => 'Backtrack limit exhausted']],
            $crsVerdict->operatorErrors
        );
    }

    public function testErroringRuleDoesNotCountAsAMatch(): void
    {
        $crsVerdict = $this->evaluate($this->ruleSet(), new FaultyOperator());

        $this->assertSame([], $crsVerdict->matchedRules);
        $this->assertSame(0, $crsVerdict->totalScore);
    }

    /**
     * The trap this guards: inverting "could not look" gives "definitely
     * matched", so a !@rx rule would turn an abandoned regex into a positive
     * detection carrying anomaly score.
     */
    public function testNegatedRuleDoesNotTurnAnErrorIntoAMatch(): void
    {
        $crsVerdict = $this->evaluate(
            $this->ruleSet(['operator_negated' => true]),
            new FaultyOperator()
        );

        $this->assertSame([], $crsVerdict->matchedRules, 'A negated error must not become a detection.');
        $this->assertSame(0, $crsVerdict->totalScore);
        $this->assertTrue($crsVerdict->hasOperatorErrors(), 'It should still be recorded as a gap.');
    }

    public function testCleanRunReportsNoOperatorErrors(): void
    {
        $crsVerdict = $this->evaluate($this->ruleSet(), new NeverMatchesOperator());

        $this->assertFalse($crsVerdict->hasOperatorErrors());
        $this->assertSame([], $crsVerdict->operatorErrors);
        $this->assertSame(CrsVerdict::ACTION_ALLOW, $crsVerdict->action);
    }

    public function testDefaultConfigDoesNotBlockOnAnOperatorError(): void
    {
        $crsVerdict = $this->evaluate($this->ruleSet(), new FaultyOperator());

        $this->assertSame(
            CrsVerdict::ACTION_ALLOW,
            $crsVerdict->action,
            'Fail-closed is opt-in; the default must not start rejecting traffic.'
        );
    }

    public function testFailClosedBlocksWhenEnabled(): void
    {
        $crsVerdict = $this->evaluate(
            $this->ruleSet(),
            new FaultyOperator(),
            new CrsConfig(paranoia: 1, failClosedOnOperatorError: true)
        );

        $this->assertSame(CrsVerdict::ACTION_BLOCK, $crsVerdict->action);
    }

    public function testFailClosedOnlyLogsInMonitorMode(): void
    {
        $crsVerdict = $this->evaluate(
            $this->ruleSet(),
            new FaultyOperator(),
            new CrsConfig(paranoia: 1, mode: CrsConfig::MODE_MONITOR, failClosedOnOperatorError: true)
        );

        $this->assertSame(CrsVerdict::ACTION_LOG, $crsVerdict->action);
    }

    public function testFailClosedDoesNotBlockACleanRequest(): void
    {
        $crsVerdict = $this->evaluate(
            $this->ruleSet(),
            new NeverMatchesOperator(),
            new CrsConfig(paranoia: 1, failClosedOnOperatorError: true)
        );

        $this->assertSame(CrsVerdict::ACTION_ALLOW, $crsVerdict->action);
    }

    /**
     * multiMatch re-runs the operator after each transform step. One step being
     * undecidable should not hide a match found at another.
     */
    public function testMultiMatchStillMatchesWhenALaterStepSucceeds(): void
    {
        $crsVerdict = $this->evaluate(
            $this->ruleSet([
                'multi_match' => true,
                'transforms'  => ['lowercase'],
                'setvars'     => [['name' => 'tx.inbound_anomaly_score_pl1', 'op' => '+', 'value' => '5']],
            ]),
            new ErrorsOnFirstCallOperator()
        );

        $this->assertNotSame([], $crsVerdict->matchedRules, 'A decidable step must still be able to match.');
    }

    public function testOperatorErrorsAppearInToArray(): void
    {
        $asArray = $this->evaluate($this->ruleSet(), new FaultyOperator())->toArray();

        $this->assertArrayHasKey('operator_errors', $asArray);
        $this->assertNotSame([], $asArray['operator_errors']);
    }
}

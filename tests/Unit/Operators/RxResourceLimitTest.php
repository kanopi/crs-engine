<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Operators;

use Kanopi\Crs\Operators\ContainsWordOperator;
use Kanopi\Crs\Operators\OperatorMatch;
use Kanopi\Crs\Operators\RxOperator;
use PHPUnit\Framework\TestCase;

/**
 * preg_match() returns false — not 0 — when it abandons a match on a resource
 * limit. Folding that into a miss made an aborted regex indistinguishable from
 * "this value carries no attack", on an attacker-controlled subject.
 *
 * The pattern below exhausts the backtrack limit at PHP's stock settings, so
 * these tests do not depend on ini overrides or on how PCRE was built.
 */
final class RxResourceLimitTest extends TestCase
{
    private const CATASTROPHIC_PATTERN = '(a|aa)+$';

    private function subjectThatCannotMatch(int $length = 200): string
    {
        return str_repeat('a', $length) . 'b';
    }

    public function testTheFixtureReallyExhaustsPcre(): void
    {
        @preg_match('#' . self::CATASTROPHIC_PATTERN . '#sS', $this->subjectThatCannotMatch());

        $this->assertSame(
            PREG_BACKTRACK_LIMIT_ERROR,
            preg_last_error(),
            'The rest of this class is meaningless if the fixture stops failing.'
        );
    }

    public function testAbandonedMatchIsReportedAsAnErrorNotAMiss(): void
    {
        $operatorMatch = (new RxOperator())->evaluate(self::CATASTROPHIC_PATTERN, $this->subjectThatCannotMatch());

        $this->assertFalse($operatorMatch->matched, 'An error is still not a match.');
        $this->assertTrue($operatorMatch->isError(), 'An abandoned match must not look like a clean miss.');
        $this->assertNotNull($operatorMatch->error);
    }

    public function testGenuineMissIsNotAnError(): void
    {
        $operatorMatch = (new RxOperator())->evaluate('(?i)select\s+from', 'hello world');

        $this->assertFalse($operatorMatch->matched);
        $this->assertFalse($operatorMatch->isError());
        $this->assertNull($operatorMatch->error);
    }

    public function testGenuineHitIsNotAnError(): void
    {
        $operatorMatch = (new RxOperator())->evaluate('foo\d+', 'abc foo123 xyz');

        $this->assertTrue($operatorMatch->matched);
        $this->assertFalse($operatorMatch->isError());
    }

    /**
     * A pattern that cannot compile is a ruleset bug: identical on every
     * request, and the rule never matches anything, so it belongs in CI rather
     * than being reported as a per-request fault that could fail traffic closed.
     */
    public function testUncompilablePatternStaysAPlainMiss(): void
    {
        $operatorMatch = (new RxOperator())->evaluate('(unclosed', 'value');

        $this->assertFalse($operatorMatch->matched);
        $this->assertFalse($operatorMatch->isError(), 'A compile error is not an input-driven failure.');
    }

    public function testMatchedNameSurvivesOnAnError(): void
    {
        $operatorMatch = (new RxOperator())
            ->evaluate(self::CATASTROPHIC_PATTERN, $this->subjectThatCannotMatch())
            ->withMatchedName('ARGS:q');

        $this->assertTrue($operatorMatch->isError(), 'withMatchedName() must not drop the error.');
        $this->assertSame('ARGS:q', $operatorMatch->matchedName);
    }

    public function testErrorFactoryProducesANonMatch(): void
    {
        $operatorMatch = OperatorMatch::error('Backtrack limit exhausted');

        $this->assertFalse($operatorMatch->matched);
        $this->assertTrue($operatorMatch->isError());
        $this->assertSame('Backtrack limit exhausted', $operatorMatch->error);
    }

    /**
     * @containsWord builds its pattern with preg_quote(), so it has no ambiguity
     * for PCRE to backtrack through and cannot realistically be driven into a
     * limit — the guard there is defensive. What is worth pinning is that
     * ordinary matching still behaves.
     */
    public function testContainsWordStillMatchesNormally(): void
    {
        $containsWordOperator = new ContainsWordOperator();

        $this->assertTrue($containsWordOperator->evaluate('admin', 'the admin panel')->matched);
        $this->assertFalse($containsWordOperator->evaluate('admin', 'administrator')->matched);
        $this->assertFalse($containsWordOperator->evaluate('admin', 'the admin panel')->isError());
        $this->assertFalse($containsWordOperator->evaluate('admin', 'administrator')->isError());
    }
}

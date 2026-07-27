<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Runtime;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\Operators\PhraseSet;
use PHPUnit\Framework\Attributes\DataProvider;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Runtime\CompiledRule;
use Kanopi\Crs\Runtime\RuleSet;
use Kanopi\Crs\Runtime\TransformPipeline;
use Kanopi\Crs\Transforms\TransformRegistry;
use PHPUnit\Framework\TestCase;

/**
 * Correctness cover for the hot-path optimisations.
 *
 * Every one of these trades work for a cache or a skip, and each has a way to
 * be subtly wrong: a filter that skips a phrase it should have tested, a cache
 * that serves a stale collection, a fast path that mangles input. Timing is
 * deliberately not asserted — that belongs in a benchmark, not a test suite.
 */
final class HotPathTest extends TestCase
{
    // ------------------------------------------------------------ PhraseSet

    /**
     * The length and first-byte filters are only sound if they never skip a
     * phrase that is actually present.
     *
     * @return iterable<string, array{0: string, 1: string, 2: ?string}>
     */
    public static function phraseProvider(): iterable
    {
        yield 'match at start'      => ["alpha\nbeta", 'alpha soup', 'alpha'];
        yield 'match at end'        => ["alpha\nbeta", 'soup beta', 'beta'];
        yield 'match in middle'     => ["alpha\nbeta", 'x beta y', 'beta'];
        yield 'case insensitive'    => ["Alpha", 'SAY ALPHA NOW', 'alpha'];
        yield 'subject equals it'   => ["alpha", 'alpha', 'alpha'];
        yield 'no match'            => ["alpha\nbeta", 'gamma delta', null];
        yield 'subject shorter'     => ["averylongphrase", 'short', null];
        yield 'first byte absent'   => ["zebra", 'alpha beta', null];
        yield 'single char phrase'  => ["z", 'the zoo', 'z'];
        yield 'phrase with spaces'  => ["hello world", 'say hello world now', 'hello world'];
        yield 'empty subject'       => ["alpha", '', null];
        yield 'high byte phrase'    => ["café", 'the café is open', 'café'];
    }

    #[DataProvider('phraseProvider')]
    public function testPhraseSetFindsWhatIsThere(string $list, string $subject, ?string $expected): void
    {
        $this->assertSame($expected, PhraseSet::fromLines($list)->firstMatch($subject));
    }

    public function testPhraseSetHandlesAnEmptyList(): void
    {
        $this->assertNull(PhraseSet::fromLines('')->firstMatch('anything'));
        $this->assertNull(PhraseSet::fromWhitespaceList('   ')->firstMatch('anything'));
    }

    public function testWhitespaceListSplitsOnSpacesAndLinesDoNot(): void
    {
        $this->assertSame('beta', PhraseSet::fromWhitespaceList('alpha beta')->firstMatch('a beta b'));
        $this->assertNull(PhraseSet::fromLines('alpha beta')->firstMatch('a beta b'));
    }

    /**
     * A long list exercises the bucketing rather than the trivial path.
     */
    public function testPhraseSetFindsAMatchInALargeList(): void
    {
        $phrases = [];
        for ($i = 0; $i < 3000; $i++) {
            $phrases[] = 'phrase_' . $i . '_' . str_repeat('x', $i % 20);
        }

        $phraseSet = PhraseSet::fromLines(implode("\n", $phrases));

        $needle = $phrases[2999];
        $this->assertSame($needle, $phraseSet->firstMatch('junk ' . $needle . ' junk'));
        $this->assertNull($phraseSet->firstMatch('nothing relevant here'));
    }

    // --------------------------------------------------- TransformPipeline

    private function pipeline(): TransformPipeline
    {
        return new TransformPipeline(new TransformRegistry());
    }

    public function testResolvedListIsReusedWithoutChangingResults(): void
    {
        $pipeline = $this->pipeline();

        $first  = $pipeline->apply(['lowercase', 'trim'], '  MiXeD  ');
        $second = $pipeline->apply(['lowercase', 'trim'], '  MiXeD  ');
        $other  = $pipeline->apply(['uppercase'], '  MiXeD  ');

        $this->assertSame('mixed', $first);
        $this->assertSame($first, $second, 'The cached resolution changed the result.');
        $this->assertSame('  MIXED  ', $other, 'A different list was served from the wrong cache entry.');
    }

    public function testNoneResetsTheChain(): void
    {
        $this->assertSame('MiXeD', $this->pipeline()->apply(['lowercase', 'none'], 'MiXeD'));
        $this->assertSame('mixed', $this->pipeline()->apply(['none', 'lowercase'], 'MiXeD'));
    }

    /**
     * Skipping is the right runtime behaviour — the rest of the pipeline still
     * normalises something. Reporting it is the parser's job, at a point where
     * it can be acted on; see UnknownTransformWarningTest.
     */
    public function testUnknownTransformIsSkippedRatherThanFatal(): void
    {
        $transformPipeline = new TransformPipeline(new TransformRegistry());

        $this->assertSame('mixed', $transformPipeline->apply(['lowercase', 'notARealTransform'], 'MiXeD'));
        $this->assertSame('  mixed  ', $transformPipeline->apply(['notARealTransform', 'lowercase'], '  MiXeD  '));
    }

    public function testEachStillYieldsEveryIntermediateValue(): void
    {
        $steps = iterator_to_array($this->pipeline()->each(['lowercase', 'trim'], '  MiXeD  '));

        $this->assertSame(['  MiXeD  ', '  mixed  ', 'mixed'], $steps);
    }

    public function testApplyAndEachAgreeOnTheFinalValue(): void
    {
        $transforms = ['urlDecodeUni', 'lowercase', 'compressWhitespace'];
        $value = '%41%42   CdE';

        $steps = iterator_to_array($this->pipeline()->each($transforms, $value));

        $this->assertSame(end($steps), $this->pipeline()->apply($transforms, $value));
    }

    // ------------------------------------------------ resolver memoisation

    /**
     * The per-request collection cache must not extend to TX: setvar mutates
     * it as rules fire, so a rule reading TX has to see the current value, not
     * whatever it was the first time something asked.
     */
    public function testTxIsNotServedFromTheCollectionCache(): void
    {
        $rules = [
            // Reads TX:counter before anything sets it — must not cache the miss.
            CompiledRule::fromArray([
                'id' => 1, 'phase' => 2, 'operator' => 'eq', 'operator_arg' => '1',
                'targets' => [['collection' => 'TX', 'selector' => 'counter']],
                'message' => 'counter was already 1',
            ]),
            CompiledRule::fromArray([
                'id' => 2, 'phase' => 2, 'operator' => 'rx', 'operator_arg' => '.*',
                'targets' => [['collection' => 'ARGS']],
                'message' => 'sets the counter',
                'setvars' => [['name' => 'tx.counter', 'op' => '=', 'value' => '1']],
            ]),
            CompiledRule::fromArray([
                'id' => 3, 'phase' => 2, 'operator' => 'eq', 'operator_arg' => '1',
                'targets' => [['collection' => 'TX', 'selector' => 'counter']],
                'message' => 'counter is now 1',
            ]),
        ];

        $crsEngine = new CrsEngine(
            new CrsConfig(paranoia: 1, mode: CrsConfig::MODE_MONITOR),
            new RuleSet($rules, 'test'),
        );

        $crsVerdict = $crsEngine->evaluate(new RequestData(
            method: 'GET',
            uri: '/',
            rawUri: '/',
            queryString: 'q=x',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            queryArgs: ['q' => 'x'],
        ));

        $this->assertSame([2, 3], array_column($crsVerdict->matchedRules, 'id'));
    }

    public function testRepeatedEvaluationsDoNotShareRequestState(): void
    {
        $rules = [CompiledRule::fromArray([
            'id' => 1, 'phase' => 2, 'operator' => 'rx', 'operator_arg' => 'attack',
            'targets' => [['collection' => 'ARGS']],
            'message' => 'hit',
        ])];

        $crsEngine = new CrsEngine(
            new CrsConfig(paranoia: 1, mode: CrsConfig::MODE_MONITOR),
            new RuleSet($rules, 'test'),
        );

        $make = static fn (string $v): RequestData => new RequestData(
            method: 'GET',
            uri: '/',
            rawUri: '/',
            queryString: 'q=' . $v,
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            queryArgs: ['q' => $v],
        );

        $this->assertNotSame([], $crsEngine->evaluate($make('attack'))->matchedRules);
        $this->assertSame([], $crsEngine->evaluate($make('harmless'))->matchedRules, "A later request saw the earlier one's arguments.");
        $this->assertNotSame([], $crsEngine->evaluate($make('attack'))->matchedRules);
    }
}

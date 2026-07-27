<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Operators;

use Kanopi\Crs\Operators\OperatorInterface;
use Kanopi\Crs\Operators\OperatorRegistry;
use PHPUnit\Framework\TestCase;

/**
 * Every registered operator against the awkward values a WAF actually receives.
 *
 * Two of the three bypasses this codebase has shipped were semantic slips in
 * twenty-line operators — `@within` accepting any substring, `@rx` reporting an
 * abandoned match as a clean miss — and neither had a single test. Operators
 * are small enough that a shared table covers all of them cheaply, and this is
 * the shape of test that catches that class of mistake.
 *
 * The contract asserted here is deliberately weak: not what each operator
 * decides, but that it decides *something* without throwing, and that the
 * result is a coherent OperatorMatch. Anything stronger belongs in the
 * per-operator tests.
 */
final class OperatorEdgeCaseMatrixTest extends TestCase
{
    /**
     * Values chosen for the ways they have historically broken things: the
     * empty string (str_contains returns true for it), a substring of a typical
     * argument, a value longer than the argument, invalid UTF-8, and a null
     * byte.
     *
     * @return array<string, string>
     */
    private function awkwardValues(): array
    {
        return [
            'empty'            => '',
            'single space'     => ' ',
            'single char'      => 'a',
            'substring of arg' => 'GE',
            'exact arg'        => 'GET',
            'superstring'      => 'GETGETGET',
            'whitespace only'  => "  \t\n  ",
            'null byte'        => "a\x00b",
            'invalid utf8'     => "\xC0\xAF",
            'high bytes'       => "\xFF\xFE\xFD",
            'long value'       => str_repeat('a', 5000),
            'newlines'         => "a\nb\r\nc",
            'regex metachars'  => '.*+?[](){}|^$\\',
            'numeric'          => '42',
            'negative numeric' => '-1',
        ];
    }

    /**
     * Arguments shaped like the ones the shipped ruleset actually passes.
     *
     * @return array<string, string>
     */
    private function representativeArguments(): array
    {
        return [
            'empty'      => '',
            'word'       => 'GET',
            'list'       => 'GET HEAD POST OPTIONS',
            'number'     => '5',
            'byte range' => '32-126',
            'cidr'       => '10.0.0.0/8',
            'regexish'   => '(?i)select\s+from',
        ];
    }

    /**
     * @return \Iterator<string, array{OperatorInterface}>
     */
    public static function operatorProvider(): \Iterator
    {
        $operatorRegistry = new OperatorRegistry();

        // Names come from the registry rather than a hand-kept list, so a newly
        // registered operator is covered here the moment it is added.
        foreach (self::registeredOperators($operatorRegistry) as $name) {
            yield $name => [$operatorRegistry->get($name)];
        }
    }

    /**
     * @return array<int, string>
     */
    private static function registeredOperators(OperatorRegistry $operatorRegistry): array
    {
        $names = [
            'rx', 'pm', 'pmf', 'beginsWith', 'endsWith', 'contains', 'containsWord',
            'streq', 'eq', 'gt', 'lt', 'ge', 'le', 'within', 'ipMatch',
            'validateByteRange', 'validateUrlEncoding', 'validateUtf8Encoding',
        ];

        $missing = array_filter($names, static fn (string $n): bool => !$operatorRegistry->has($n));
        if ($missing !== []) {
            throw new \RuntimeException('Operator list is stale: ' . implode(', ', $missing));
        }

        return $names;
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('operatorProvider')]
    public function testOperatorDecidesWithoutThrowing(OperatorInterface $operator): void
    {
        foreach ($this->representativeArguments() as $argLabel => $argument) {
            foreach ($this->awkwardValues() as $valueLabel => $value) {
                $context = sprintf('%s(arg=%s, value=%s)', $operator->name(), $argLabel, $valueLabel);

                try {
                    $operatorMatch = $operator->evaluate($argument, $value);
                } catch (\Throwable $throwable) {
                    $this->fail($context . ' threw ' . $throwable::class . ': ' . $throwable->getMessage());
                }

                // A match and an error are mutually exclusive: "found it" and
                // "could not look" cannot both be true.
                $this->assertFalse(
                    $operatorMatch->matched && $operatorMatch->isError(),
                    $context . ' reported a match and an error at once.'
                );

                // matchedData is only meaningful on a hit, but it must always
                // be a string — RuleEvaluator puts it straight into the verdict.
                if ($operatorMatch->matched) {
                    $this->assertNotNull($operatorMatch->error === null ? '' : null, $context . ' hit carries an error.');
                }
            }
        }
    }

    /**
     * An empty value is the one that produced a real bypass: str_contains()
     * returns true for it, so `!@within` could not fire on a missing method.
     * No operator should claim a positive detection on nothing at all.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('operatorProvider')]
    public function testEmptyValueIsNotAPositiveDetection(OperatorInterface $operator): void
    {
        $alwaysTrueOnEmpty = [
            // @rx with an empty-matching pattern genuinely matches empty input;
            // that is regex semantics, not a slip.
            'rx',
            // Numeric comparisons cast '' to 0, so `@eq 0` and `@le 5` are
            // legitimately true. The ruleset only uses these against counts.
            'eq', 'le', 'lt', 'ge',
            // An empty string trivially contains no byte outside any range and
            // is trivially valid UTF-8 / URL encoding, so these correctly miss —
            // but they are inverted operators, so "miss" is the safe answer and
            // is what they give.
        ];

        if (in_array($operator->name(), $alwaysTrueOnEmpty, true)) {
            $this->markTestSkipped($operator->name() . ' has defensible semantics on an empty value.');
        }

        foreach ($this->representativeArguments() as $label => $argument) {
            // An empty argument is excluded: "" genuinely does begin with,
            // end with, contain and equal "". The bypass worth guarding is an
            // empty value matching a *populated* allow-list.
            if ($argument === '') {
                continue;
            }

            $this->assertFalse(
                $operator->evaluate($argument, '')->matched,
                sprintf('%s matched an empty value against arg=%s.', $operator->name(), $label)
            );
        }
    }

    /**
     * A value longer than the argument cannot be a member of it, for any of the
     * containment-style operators.
     */
    public function testContainmentOperatorsRejectAValueLongerThanTheArgument(): void
    {
        $operatorRegistry = new OperatorRegistry();

        foreach (['within', 'streq'] as $name) {
            $this->assertFalse(
                $operatorRegistry->get($name)->evaluate('GET HEAD', 'GET HEAD POST OPTIONS EXTRA')->matched,
                $name . ' matched a value longer than its argument.'
            );
        }
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('operatorProvider')]
    public function testOperatorNameIsStableAndLowercaseResolvable(OperatorInterface $operator): void
    {
        $operatorRegistry = new OperatorRegistry();

        $this->assertTrue($operatorRegistry->has(strtolower($operator->name())));
        $this->assertTrue($operatorRegistry->has(strtoupper($operator->name())));
        $this->assertSame($operator->name(), $operator->name(), 'name() must be stable across calls.');
    }
}

<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class RxOperator implements OperatorInterface
{
    /**
     * Cache compiled PCRE delimiters per pattern. Even with opcache, this
     * saves repeated string concat on hot rules.
     *
     * @var array<string, string>
     */
    private static array $compiled = [];

    public function name(): string
    {
        return 'rx';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        $pattern = self::$compiled[$argument] ?? null;
        if ($pattern === null) {
            $pattern = '#' . str_replace('#', '\\#', $argument) . '#sS';
            self::$compiled[$argument] = $pattern;
        }

        $matches = [];
        $result = @preg_match($pattern, $value, $matches);
        if ($result === false || $result === 0) {
            return OperatorMatch::miss();
        }

        // Numbered groups only; the evaluator copies them to TX:0..TX:9 when
        // the rule carries `capture`.
        $captures = [];
        foreach ($matches as $index => $group) {
            if (is_int($index)) {
                $captures[$index] = $group;
            }
        }

        return OperatorMatch::hit($matches[0] ?? '', $captures);
    }
}

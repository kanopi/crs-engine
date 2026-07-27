<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

final class OperatorMatch
{
    /**
     * @param array<int, string> $captures Numbered regex groups, group 0 first.
     *        Only populated by operators that have them; written to TX:0..TX:9
     *        by the evaluator when the rule carries `capture`.
     * @param string|null $matchedName Where the matching value came from, e.g.
     *        `ARGS:id`. Backs %{MATCHED_VAR_NAME}. Attached by the evaluator,
     *        which knows the target; operators only ever see the value.
     */
    public function __construct(
        public readonly bool $matched,
        public readonly string $matchedData = '',
        public readonly array $captures = [],
        public readonly ?string $matchedName = null,
    ) {
    }

    public static function miss(): self
    {
        return new self(false);
    }

    /**
     * @param array<int, string> $captures
     */
    public static function hit(string $matchedData = '', array $captures = []): self
    {
        return new self(true, $matchedData, $captures);
    }

    /**
     * Copy carrying the target this value was resolved from.
     */
    public function withMatchedName(?string $matchedName): self
    {
        return new self($this->matched, $this->matchedData, $this->captures, $matchedName);
    }
}

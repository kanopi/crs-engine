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
     * @param string|null $error Set when the operator could not reach a verdict
     *        on this value — a PCRE resource limit, say. Distinct from a miss:
     *        a miss means "no attack here", an error means "did not look".
     *        Never both; an error is always reported with matched = false.
     */
    public function __construct(
        public readonly bool $matched,
        public readonly string $matchedData = '',
        public readonly array $captures = [],
        public readonly ?string $matchedName = null,
        public readonly ?string $error = null,
    ) {
    }

    public static function miss(): self
    {
        return new self(false);
    }

    /**
     * The operator aborted rather than deciding. Reported as not-matched so
     * existing callers behave as before, but the reason travels with it so the
     * evaluator can record that this rule did not actually get to run.
     */
    public static function error(string $reason): self
    {
        return new self(false, error: $reason);
    }

    public function isError(): bool
    {
        return $this->error !== null;
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
        return new self($this->matched, $this->matchedData, $this->captures, $matchedName, $this->error);
    }
}

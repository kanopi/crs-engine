<?php

declare(strict_types=1);

namespace Kanopi\Crs;

final class CrsVerdict
{
    public const ACTION_ALLOW = 'allow';

    public const ACTION_LOG   = 'log';

    public const ACTION_BLOCK = 'block';

    /**
     * @param array<string, int> $scores Category => accumulated anomaly score
     * @param array<int, array{id: int, msg: string, severity: string, score: int, tags: array<int, string>, category: string, matched_data: string, logdata: ?string}> $matchedRules
     * @param array<int, array{rule_id: int, operator: string, error: string}> $operatorErrors
     *        Rules that could not be evaluated — a regex abandoned on a PCRE
     *        resource limit, say. Not the same as a rule that found nothing:
     *        these are gaps in coverage for this request, and a clean verdict
     *        alongside a non-empty list here means less was inspected than it
     *        appears. Worth alerting on.
     * @param array<int, array{what: string, inspected: int, total: int}> $truncations
     *        Where an inspection cap cut this request short — too many
     *        arguments, or a body larger than maxBodyBytes. Like
     *        $operatorErrors these are coverage gaps rather than findings, but
     *        deliberate ones: the caps exist so an oversized request cannot buy
     *        unbounded CPU. `&ARGS` counting is never capped, so the CRS rules
     *        that flag an over-large request still fire.
     */
    public function __construct(
        public readonly string $action,
        public readonly array $scores,
        public readonly array $matchedRules,
        public readonly int $totalScore,
        public readonly ?int $blockingRuleId = null,
        public readonly array $operatorErrors = [],
        public readonly array $truncations = [],
    ) {
    }

    public function isBlocked(): bool
    {
        return $this->action === self::ACTION_BLOCK;
    }

    /**
     * True when at least one rule could not be evaluated against this request.
     */
    public function hasOperatorErrors(): bool
    {
        return $this->operatorErrors !== [];
    }

    /**
     * True when an inspection cap stopped part of this request being examined.
     */
    public function wasTruncated(): bool
    {
        return $this->truncations !== [];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'action'            => $this->action,
            'total_score'       => $this->totalScore,
            'scores'            => $this->scores,
            'blocking_rule_id'  => $this->blockingRuleId,
            'matched_rules'     => $this->matchedRules,
            'operator_errors'   => $this->operatorErrors,
            'truncations'       => $this->truncations,
        ];
    }
}

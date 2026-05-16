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
     * @param array<int, array{id: int, msg: string, severity: string, score: int, tags: array<int, string>, category: string, matched_data: string}> $matchedRules
     */
    public function __construct(
        public readonly string $action,
        public readonly array $scores,
        public readonly array $matchedRules,
        public readonly int $totalScore,
        public readonly ?int $blockingRuleId = null,
    ) {
    }

    public function isBlocked(): bool
    {
        return $this->action === self::ACTION_BLOCK;
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
        ];
    }
}

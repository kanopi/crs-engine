<?php

declare(strict_types=1);

namespace Kanopi\Crs\Runtime;

/**
 * In-memory representation of a parsed CRS rule, optimised for evaluation.
 *
 * @phpstan-type TargetSpec array{collection: string, selector?: ?string, negated?: bool, count?: bool, regex?: bool}
 * @phpstan-type SetVarOp array{name: string, op: string, value: string}
 */
final class CompiledRule
{
    /**
     * @param array<int, TargetSpec> $targets
     * @param array<int, string> $transforms
     * @param array<int, string> $tags
     * @param array<int, SetVarOp> $setvars
     * @param array<int, CompiledRule> $chain
     * @param string|null $logdata Diagnostic template from the rule, surfaced on the verdict.
     * @param string|null $marker Non-null only for SecMarker placeholders, which
     *        carry no operator and exist purely as skipAfter landing points.
     * @param array<int, int> $suppressRuleIds Rules switched off for the rest of
     *        this transaction once this one matches (ctl:ruleRemoveById).
     * @param array<int, string> $suppressRuleTags As above, by tag.
     */
    public function __construct(
        public readonly int $id,
        public readonly int $phase,
        public readonly string $operator,
        public readonly string $operatorArgument,
        public readonly bool $operatorNegated,
        public readonly array $targets,
        public readonly array $transforms,
        public readonly string $action,
        public readonly string $severity,
        public readonly string $message,
        public readonly array $tags,
        public readonly int $paranoia,
        public readonly string $category,
        public readonly array $setvars,
        public readonly array $chain,
        public readonly bool $capture,
        public readonly ?string $skipAfter,
        public readonly bool $multiMatch,
        public readonly ?string $logdata = null,
        public readonly ?string $marker = null,
        public readonly bool $unconditional = false,
        public readonly array $suppressRuleIds = [],
        public readonly array $suppressRuleTags = [],
    ) {
    }

    /**
     * True for SecAction directives, which have no operator and apply their
     * actions to every request.
     */
    public function isUnconditional(): bool
    {
        return $this->unconditional;
    }

    /**
     * True for SecMarker placeholders — no operator to evaluate, present only
     * so a preceding skipAfter has a landing point.
     */
    public function isMarker(): bool
    {
        return $this->marker !== null;
    }

    /**
     * @param array{
     *     id?: int,
     *     phase?: int,
     *     operator?: string,
     *     operator_arg?: string,
     *     operator_negated?: bool,
     *     targets?: array<int, TargetSpec>,
     *     transforms?: array<int, string>,
     *     action?: string,
     *     severity?: string,
     *     message?: string,
     *     tags?: array<int, string>,
     *     paranoia?: int,
     *     category?: string,
     *     setvars?: array<int, SetVarOp>,
     *     chain?: array<int, array<string, mixed>>,
     *     capture?: bool,
     *     skip_after?: ?string,
     *     multi_match?: bool,
     *     logdata?: ?string,
     *     marker?: ?string,
     *     unconditional?: bool,
     *     suppress_rule_ids?: array<int, int>,
     *     suppress_rule_tags?: array<int, string>
     * } $data
     */
    public static function fromArray(array $data): self
    {
        $chain = [];
        foreach (($data['chain'] ?? []) as $sub) {
            /** @var array<string, mixed> $sub */
            $chain[] = self::fromArray($sub);
        }

        return new self(
            id:               $data['id'] ?? 0,
            phase:            $data['phase'] ?? 2,
            operator:         $data['operator'] ?? 'rx',
            operatorArgument: $data['operator_arg'] ?? '',
            operatorNegated:  $data['operator_negated'] ?? false,
            targets:          $data['targets'] ?? [],
            transforms:       $data['transforms'] ?? [],
            action:           $data['action'] ?? 'pass',
            severity:         $data['severity'] ?? 'notice',
            message:          $data['message'] ?? '',
            tags:             $data['tags'] ?? [],
            paranoia:         $data['paranoia'] ?? 1,
            category:         $data['category'] ?? 'unknown',
            setvars:          $data['setvars'] ?? [],
            chain:            $chain,
            capture:          $data['capture'] ?? false,
            skipAfter:        $data['skip_after'] ?? null,
            multiMatch:       $data['multi_match'] ?? false,
            logdata:          $data['logdata'] ?? null,
            marker:           $data['marker'] ?? null,
            unconditional:    $data['unconditional'] ?? false,
            suppressRuleIds:  $data['suppress_rule_ids'] ?? [],
            suppressRuleTags: $data['suppress_rule_tags'] ?? [],
        );
    }
}

<?php

declare(strict_types=1);

namespace Kanopi\Crs\Parser;

/**
 * Output of the SecLang parser. Mirrors CompiledRule but kept separate so
 * the parser stage doesn't depend on runtime classes.
 */
final class ParsedRule
{
    /**
     * @param array<int, array<string, mixed>> $targets
     * @param array<int, string> $transforms
     * @param array<int, string> $tags
     * @param array<int, array{name: string, op: string, value: string}> $setvars
     * @param array<int, ParsedRule> $chain
     * @param array<int, string> $warnings
     * @param string|null $marker Non-null only for SecMarker placeholders, which
     *        carry no operator and exist purely as skipAfter landing points.
     * @param array<int, int> $suppressRuleIds Rules this one switches off for the
     *        rest of the transaction when it matches (ctl:ruleRemoveById).
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
        public readonly array $warnings,
        public readonly ?string $logdata = null,
        public readonly ?string $marker = null,
        public readonly bool $unconditional = false,
        public readonly array $suppressRuleIds = [],
        public readonly array $suppressRuleTags = [],
    ) {
    }

    /**
     * A SecAction — an unconditional directive that applies its actions to
     * every request. CRS uses them for bookkeeping, most importantly to reset
     * the aggregate anomaly scores at the start of phase 2 so per-paranoia-level
     * scores are not counted twice across phases.
     *
     * @param array<int, array{name: string, op: string, value: string}> $setvars
     * @param array<int, string> $tags
     */
    public static function unconditional(int $id, int $phase, array $setvars, array $tags, string $category): self
    {
        return new self(
            id:               $id,
            phase:            $phase,
            operator:         '',
            operatorArgument: '',
            operatorNegated:  false,
            targets:          [],
            transforms:       [],
            action:           'pass',
            severity:         'notice',
            message:          '',
            tags:             $tags,
            paranoia:         1,
            category:         $category,
            setvars:          $setvars,
            chain:            [],
            capture:          false,
            skipAfter:        null,
            multiMatch:       false,
            warnings:         [],
            unconditional:    true,
        );
    }

    /**
     * A SecMarker placeholder. Holds position in the rule list so that a
     * preceding skipAfter has somewhere to land; never evaluated.
     */
    public static function marker(string $name, string $category): self
    {
        return new self(
            id:               0,
            phase:            0,
            operator:         '',
            operatorArgument: '',
            operatorNegated:  false,
            targets:          [],
            transforms:       [],
            action:           'pass',
            severity:         'notice',
            message:          '',
            tags:             [],
            paranoia:         1,
            category:         $category,
            setvars:          [],
            chain:            [],
            capture:          false,
            skipAfter:        null,
            multiMatch:       false,
            warnings:         [],
            marker:           $name,
            unconditional:    false,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $chain = [];
        foreach ($this->chain as $c) {
            $chain[] = $c->toArray();
        }

        return [
            'id'                => $this->id,
            'phase'             => $this->phase,
            'operator'          => $this->operator,
            'operator_arg'      => $this->operatorArgument,
            'operator_negated'  => $this->operatorNegated,
            'targets'           => $this->targets,
            'transforms'        => $this->transforms,
            'action'            => $this->action,
            'severity'          => $this->severity,
            'message'           => $this->message,
            'tags'              => $this->tags,
            'paranoia'          => $this->paranoia,
            'category'          => $this->category,
            'setvars'           => $this->setvars,
            'chain'             => $chain,
            'capture'           => $this->capture,
            'skip_after'        => $this->skipAfter,
            'multi_match'       => $this->multiMatch,
            'warnings'          => $this->warnings,
            'logdata'           => $this->logdata,
            'marker'            => $this->marker,
            'unconditional'     => $this->unconditional,
            'suppress_rule_ids'  => $this->suppressRuleIds,
            'suppress_rule_tags' => $this->suppressRuleTags,
        ];
    }
}

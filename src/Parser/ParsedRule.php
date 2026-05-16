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
    ) {
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
        ];
    }
}

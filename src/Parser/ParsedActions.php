<?php

declare(strict_types=1);

namespace Kanopi\Crs\Parser;

/**
 * Internal DTO holding the parsed contents of a SecRule's action list.
 * Used only inside the parser; CompiledRule is the public runtime form.
 *
 * @internal
 */
final class ParsedActions
{
    /**
     * @param array<int, string> $transforms
     * @param array<int, string> $tags
     * @param array<int, array{name: string, op: string, value: string}> $setvars
     */
    public function __construct(
        public int $id = 0,
        public int $phase = 2,
        public string $action = 'pass',
        public string $severity = 'notice',
        public string $message = '',
        public array $transforms = [],
        public array $tags = [],
        public array $setvars = [],
        public bool $capture = false,
        public bool $multiMatch = false,
        public bool $chain = false,
        public ?string $skipAfter = null,
        public ?string $logdata = null,
    ) {
    }
}

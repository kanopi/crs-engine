<?php

declare(strict_types=1);

namespace Kanopi\Crs\Refresh;

use Kanopi\Crs\Parser\SecLangParser;

/**
 * High-level orchestration for `bin/refresh-crs`. Keeps the CLI script
 * itself tiny and lets us unit-test the refresh flow.
 */
final class RefreshRunner
{
    public function __construct(
        private readonly VersionPin $versionPin,
        private readonly CrsFetcher $crsFetcher,
        private readonly RuleWriter $ruleWriter,
        private readonly string $workDir,
    ) {
    }

    /**
     * @return array{tag: string, rule_count: int, file_count: int, warnings: int, parser_warnings: array<int, string>}
     */
    public function run(?string $tagOverride = null, bool $bump = false): array
    {
        $pinData = $this->versionPin->read();
        $tag = $tagOverride ?? $pinData['tag'];

        if ($bump) {
            $latest = $this->crsFetcher->latestTag();
            if ($latest !== $tag) {
                $tag = $latest;
            }
        }

        $rulesPath = $this->crsFetcher->fetchTag($tag, $this->workDir);
        $secLangParser    = new SecLangParser();

        $rulesBySource = [];
        $confFiles = array_merge(
            glob($rulesPath . '/REQUEST-*.conf') ?: [],
            glob($rulesPath . '/RESPONSE-*.conf') ?: [],
        );
        foreach ($confFiles as $confFile) {
            $base = basename($confFile);
            // 901-INITIALIZATION and 905-COMMON-EXCEPTIONS are CRS's own
            // configuration scaffolding normally driven by crs-setup.conf —
            // we replace that with CrsConfig, so parsing them in causes
            // rule 901001 to deny every request because tx.crs_setup_version
            // is never set.
            if (str_contains($base, 'INITIALIZATION')) {
                continue;
            }

            if (str_contains($base, 'COMMON-EXCEPTIONS')) {
                continue;
            }

            $rules = $secLangParser->parseFile($confFile);
            if ($rules !== []) {
                $rulesBySource[$base] = $rules;
            }
        }

        $stats = $this->ruleWriter->write($rulesBySource, $tag, $secLangParser->warnings);
        $this->versionPin->write(['tag' => $tag]);

        return [
            'tag'             => $tag,
            'rule_count'      => $stats['rule_count'],
            'file_count'      => $stats['file_count'],
            'warnings'        => $stats['warnings'],
            'parser_warnings' => $secLangParser->warnings,
        ];
    }
}

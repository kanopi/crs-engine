<?php

declare(strict_types=1);

namespace Kanopi\Crs\Refresh;

use Kanopi\Crs\Exception\CrsEngineException;
use Kanopi\Crs\Parser\SecLangParser;

/**
 * High-level orchestration for `bin/refresh-crs`. Keeps the CLI script
 * itself tiny and lets us unit-test the refresh flow.
 */
final class RefreshRunner
{
    /**
     * @param string|null $supplementalDir Engine-owned SecLang files parsed
     *        alongside CRS. They live outside rules/, which the refresh
     *        regenerates, so they survive CRS version bumps.
     */
    public function __construct(
        private readonly VersionPin $versionPin,
        private readonly CrsSource $crsSource,
        private readonly RuleWriter $ruleWriter,
        private readonly string $workDir,
        private readonly ?string $supplementalDir = null,
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
            $latest = $this->crsSource->latestTag();
            if ($latest !== $tag) {
                $tag = $latest;
            }
        }

        $rulesPath = $this->crsSource->fetchTag($tag, $this->workDir);

        // Verify before parsing, so a substituted ruleset never reaches the
        // writer and rules/ is left exactly as it was.
        $digest = RulesetDigest::forDirectory($rulesPath);
        $expected = $bump ? '' : $pinData['sha'];
        $digestState = $this->verifyDigest($expected, $digest, $tag);

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

        // Supplemental files are keyed by filename like any other source, so
        // RuleWriter's ksort drops them into position. REQUEST-948-* lands
        // between the last CRS detection file and REQUEST-949 blocking
        // evaluation, which is where a scoring rule has to sit to be counted.
        foreach ($this->supplementalFiles() as $confFile) {
            $rules = $secLangParser->parseFile($confFile);
            if ($rules !== []) {
                $rulesBySource[basename($confFile)] = $rules;
            }
        }

        $stats = $this->ruleWriter->write($rulesBySource, $tag, $secLangParser->warnings);
        $this->versionPin->write(['tag' => $tag, 'sha' => $digest]);

        return [
            'tag'             => $tag,
            'rule_count'      => $stats['rule_count'],
            'file_count'      => $stats['file_count'],
            'warnings'        => $stats['warnings'],
            'parser_warnings' => $secLangParser->warnings,
            'digest'          => $digest,
            'digest_state'    => $digestState,
        ];
    }

    /**
     * @return 'verified'|'recorded' What happened to the content pin.
     */
    private function verifyDigest(string $expected, string $actual, string $tag): string
    {
        if ($expected === '') {
            // No pin recorded yet, or --bump deliberately moving to new
            // content. Record what we fetched so the next run can verify it.
            return 'recorded';
        }

        if (!hash_equals($expected, $actual)) {
            throw new CrsEngineException(sprintf(
                "CRS content digest mismatch for %s.\n  expected %s\n  got      %s\n"
                . "The rules published under this tag are not the rules that were pinned. "
                . "rules/ has been left untouched. Re-pin deliberately with --bump if this change is expected.",
                $tag,
                $expected,
                $actual,
            ));
        }

        return 'verified';
    }

    /**
     * @return array<int, string>
     */
    private function supplementalFiles(): array
    {
        if ($this->supplementalDir === null || !is_dir($this->supplementalDir)) {
            return [];
        }

        $files = glob(rtrim($this->supplementalDir, '/') . '/*.conf') ?: [];
        sort($files);

        return $files;
    }
}

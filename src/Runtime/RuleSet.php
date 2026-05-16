<?php

declare(strict_types=1);

namespace Kanopi\Crs\Runtime;

use Kanopi\Crs\Exception\ConfigurationException;

final class RuleSet
{
    /**
     * Process-local memo of directory => RuleSet, so subsequent requests
     * served by the same PHP-FPM worker (or long-lived CLI process) skip
     * the ~2-4ms rule materialization cost. Reset only when the worker
     * recycles, which is also when CRS rule updates take effect.
     *
     * Zero-dependency: no APCu, no opcache preload, no Redis required.
     * For cross-process sharing, integrators can wrap loadFromDirectory in
     * their own cache and pass the resulting RuleSet to CrsEngine.
     *
     * @var array<string, self>
     */
    private static array $processCache = [];

    /** @var array<int, CompiledRule> */
    private array $rules = [];

    /**
     * @param array<int, CompiledRule> $rules
     */
    public function __construct(array $rules = [], private readonly string $crsVersion = '')
    {
        foreach ($rules as $rule) {
            $this->add($rule);
        }
    }

    public function add(CompiledRule $compiledRule): void
    {
        $this->rules[] = $compiledRule;
    }

    public function crsVersion(): string
    {
        return $this->crsVersion;
    }

    /**
     * @return array<int, CompiledRule>
     */
    public function all(): array
    {
        return $this->rules;
    }

    public function count(): int
    {
        return count($this->rules);
    }

    /**
     * Load the engine's compiled rule cache. Prefers rules/compiled.php
     * (a var_export'd PHP array opcache loves) and falls back to
     * rules/manifest.json + rules/*.json for environments where the
     * compiled cache hasn't been generated yet.
     *
     * Memoised per directory for the lifetime of the PHP process — see
     * $processCache. Pass useCache: false to force a re-read (useful for
     * tests that swap rules on disk between loads).
     */
    public static function loadFromDirectory(string $directory, bool $useCache = true): self
    {
        $directory = rtrim($directory, '/');

        if ($useCache && isset(self::$processCache[$directory])) {
            return self::$processCache[$directory];
        }

        $compiled  = $directory . '/compiled.php';

        if (is_file($compiled)) {
            /** @var array{version: string, rules: array<int, array<string, mixed>>} $data */
            $data = require $compiled;
            $ruleSet = self::fromCompiledArray($data);
            if ($useCache) {
                self::$processCache[$directory] = $ruleSet;
            }

            return $ruleSet;
        }

        $manifest = $directory . '/manifest.json';
        if (!is_file($manifest)) {
            throw new ConfigurationException(sprintf('No rules found at %s; run bin/refresh-crs to generate them.', $directory));
        }

        /** @var array{version?: string, files: array<int, string>} $manifestData */
        $manifestData = json_decode((string) file_get_contents($manifest), true, flags: JSON_THROW_ON_ERROR);
        $rules = [];
        foreach ($manifestData['files'] as $file) {
            $path = $directory . '/' . $file;
            if (!is_file($path)) {
                continue;
            }

            /** @var array{rules: array<int, array<string, mixed>>} $fileData */
            $fileData = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
            foreach ($fileData['rules'] as $r) {
                $rules[] = CompiledRule::fromArray($r);
            }
        }

        $ruleSet = new self($rules, $manifestData['version'] ?? '');
        if ($useCache) {
            self::$processCache[$directory] = $ruleSet;
        }

        return $ruleSet;
    }

    /**
     * Drop the process-local memo. Tests that rewrite the rules/ directory
     * mid-suite need this; production code never has to call it.
     */
    public static function clearProcessCache(): void
    {
        self::$processCache = [];
    }

    /**
     * @param array{version?: string, rules: array<int, array<string, mixed>>} $data
     */
    public static function fromCompiledArray(array $data): self
    {
        $rules = [];
        foreach ($data['rules'] as $r) {
            $rules[] = CompiledRule::fromArray($r);
        }

        return new self($rules, $data['version'] ?? '');
    }
}

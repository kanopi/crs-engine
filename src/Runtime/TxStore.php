<?php

declare(strict_types=1);

namespace Kanopi\Crs\Runtime;

/**
 * Per-request KV store backing CRS's TX variables. Holds anomaly score
 * accumulators (tx.sql_injection_score, tx.xss_score, ...) and any
 * setvar:tx.* state. Resets between requests.
 */
final class TxStore
{
    /** @var array<string, string> */
    private array $vars = [];

    public function get(string $key): ?string
    {
        return $this->vars[strtolower($key)] ?? null;
    }

    public function getInt(string $key): int
    {
        return (int) ($this->vars[strtolower($key)] ?? '0');
    }

    public function set(string $key, string $value): void
    {
        $this->vars[strtolower($key)] = $value;
    }

    public function increment(string $key, int $by = 1): int
    {
        $cur = $this->getInt($key);
        $new = $cur + $by;
        $this->set($key, (string) $new);
        return $new;
    }

    public function decrement(string $key, int $by = 1): int
    {
        return $this->increment($key, -$by);
    }

    public function unset(string $key): void
    {
        unset($this->vars[strtolower($key)]);
    }

    public function has(string $key): bool
    {
        return isset($this->vars[strtolower($key)]);
    }

    /**
     * @return array<string, string>
     */
    public function all(): array
    {
        return $this->vars;
    }
}

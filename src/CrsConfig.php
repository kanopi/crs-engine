<?php

declare(strict_types=1);

namespace Kanopi\Crs;

use Kanopi\Crs\Exception\ConfigurationException;

final class CrsConfig
{
    public const MODE_BLOCK   = 'block';

    public const MODE_MONITOR = 'monitor';

    /**
     * @param int $paranoia Paranoia level 1-4. Rules tagged with a higher PL are skipped.
     * @param string $mode block | monitor
     * @param array<string, int> $anomalyThresholds Severity key => required score to block
     * @param array<int, int> $disabledRules Rule IDs to never evaluate
     * @param array<int, string> $disabledCategories Category slugs to skip
     * @param string|null $rulesPath Override location of compiled rules. Defaults to bundled rules/.
     */
    public function __construct(
        public readonly int $paranoia = 1,
        public readonly string $mode = self::MODE_BLOCK,
        public readonly array $anomalyThresholds = [
            'critical' => 5,
            'error'    => 4,
            'warning'  => 3,
            'notice'   => 2,
        ],
        public readonly array $disabledRules = [],
        public readonly array $disabledCategories = [],
        public readonly ?string $rulesPath = null,
    ) {
        if ($paranoia < 1 || $paranoia > 4) {
            throw new ConfigurationException('Paranoia level must be between 1 and 4, got ' . $paranoia);
        }

        if (!in_array($mode, [self::MODE_BLOCK, self::MODE_MONITOR], true)) {
            throw new ConfigurationException(sprintf("Mode must be 'block' or 'monitor', got '%s'", $mode));
        }
    }

    /**
     * @param array{
     *     paranoia?: int,
     *     mode?: string,
     *     anomaly_thresholds?: array<string, int>,
     *     disabled_rules?: array<int, int|string>,
     *     disabled_categories?: array<int, string>,
     *     rules_path?: ?string
     * } $config
     */
    public static function fromArray(array $config): self
    {
        return new self(
            paranoia:           $config['paranoia'] ?? 1,
            mode:               $config['mode'] ?? self::MODE_BLOCK,
            anomalyThresholds:  $config['anomaly_thresholds'] ?? [
                'critical' => 5,
                'error'    => 4,
                'warning'  => 3,
                'notice'   => 2,
            ],
            disabledRules:      array_map(intval(...), $config['disabled_rules'] ?? []),
            disabledCategories: $config['disabled_categories'] ?? [],
            rulesPath:          $config['rules_path'] ?? null,
        );
    }

    public function isRuleDisabled(int $ruleId): bool
    {
        return in_array($ruleId, $this->disabledRules, true);
    }

    public function isCategoryDisabled(string $category): bool
    {
        return in_array($category, $this->disabledCategories, true);
    }
}

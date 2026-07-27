<?php

declare(strict_types=1);

namespace Kanopi\Crs;

use Kanopi\Crs\Exception\ConfigurationException;

final class CrsConfig
{
    public const MODE_BLOCK   = 'block';

    public const MODE_MONITOR = 'monitor';

    /** Requests are blocked once the inbound anomaly score reaches this. */
    public const THRESHOLD_INBOUND = 'inbound';

    /** Responses are blocked once the outbound anomaly score reaches this. */
    public const THRESHOLD_OUTBOUND = 'outbound';

    /**
     * Pre-4.0 spellings. They read as one threshold per severity, but there
     * are only ever two thresholds and they are directional.
     *
     * @var array<string, string>
     */
    private const THRESHOLD_ALIASES = [
        'critical' => self::THRESHOLD_INBOUND,
        'error'    => self::THRESHOLD_OUTBOUND,
    ];

    /**
     * Accepted but inert before the rename — they never mapped to a threshold.
     *
     * @var array<int, string>
     */
    private const THRESHOLD_IGNORED = ['warning', 'notice'];

    public const DEFAULT_THRESHOLDS = [
        self::THRESHOLD_INBOUND  => 5,
        self::THRESHOLD_OUTBOUND => 4,
    ];

    /**
     * Arguments whose values are run through the ruleset. Matches CRS's own
     * tx.max_num_args, so a request carrying more is already anomalous by
     * upstream's reckoning — 920380 flags it, and that rule still sees the true
     * count because only value inspection is capped, not counting.
     */
    public const DEFAULT_MAX_ARGS = 255;

    /**
     * Body bytes handed to the ruleset, matching ModSecurity's
     * SecRequestBodyNoFilesLimit default. Cost is roughly linear in this, and
     * the body is entirely attacker-controlled.
     */
    public const DEFAULT_MAX_BODY_BYTES = 131072;

    /**
     * Total bytes of argument values a single rule will inspect.
     *
     * Capping the argument *count* alone does not bound the work: one 2.5 MB
     * argument costs as much as ten thousand small ones. Cost is the product of
     * rules and bytes, so bytes need their own ceiling. CRS 920390 already
     * flags a request whose total argument length exceeds tx.total_arg_length
     * (64000), so a request above this is anomalous upstream too.
     */
    public const DEFAULT_MAX_ARG_BYTES = 131072;

    /** Disables a cap. Inspect everything, whatever it costs. */
    public const UNLIMITED = -1;

    /**
     * How much each severity contributes to the anomaly score. Upstream CRS
     * exposes these in crs-setup.conf and operators do tune them.
     */
    public const DEFAULT_SEVERITY_SCORES = [
        'critical' => 5,
        'error'    => 4,
        'warning'  => 3,
        'notice'   => 2,
    ];

    /**
     * Normalised to the two directional keys, whatever spelling came in.
     *
     * @var array<string, int>
     */
    public readonly array $anomalyThresholds;

    /** @var array<string, int> */
    public readonly array $severityScores;

    /**
     * @param int $paranoia Paranoia level 1-4. Rules tagged with a higher PL are skipped.
     * @param string $mode block | monitor
     * @param array<string, int> $anomalyThresholds Score at which to block, keyed by
     *        direction: `inbound` for requests, `outbound` for responses. The
     *        old `critical`/`error` spellings are accepted as deprecated aliases.
     * @param array<int, int> $disabledRules Rule IDs to never evaluate
     * @param array<int, string> $disabledCategories Category slugs to skip
     * @param string|null $rulesPath Override location of compiled rules. Defaults to bundled rules/.
     * @param array<string, int> $severityScores Anomaly contribution per severity
     *        (critical/error/warning/notice). These are what rules *add*; the
     *        thresholds above are what the total is compared against.
     * @param bool $failClosedOnOperatorError Whether a request whose evaluation
     *        hit an operator error — a rule that could not run rather than one
     *        that found nothing — should be treated as blocked. Off by default
     *        because turning it on can reject traffic that previously passed;
     *        CrsVerdict::$operatorErrors is populated either way, so the
     *        condition is observable before anyone acts on it.
     * @param int $maxArgs How many argument values to run through the ruleset.
     *        Counting is unaffected, so `&ARGS` rules still see the real total.
     *        CrsConfig::UNLIMITED to inspect every argument.
     * @param int $maxBodyBytes How much of the request or response body to hand
     *        to the ruleset. CrsConfig::UNLIMITED to inspect all of it.
     * @param int $maxArgBytes Total bytes of argument values a single rule will
     *        inspect. Bounds the work a few very large arguments can buy, which
     *        $maxArgs alone does not. CrsConfig::UNLIMITED to inspect all of it.
     */
    public function __construct(
        public readonly int $paranoia = 1,
        public readonly string $mode = self::MODE_BLOCK,
        array $anomalyThresholds = self::DEFAULT_THRESHOLDS,
        public readonly array $disabledRules = [],
        public readonly array $disabledCategories = [],
        public readonly ?string $rulesPath = null,
        array $severityScores = self::DEFAULT_SEVERITY_SCORES,
        public readonly bool $failClosedOnOperatorError = false,
        public readonly int $maxArgs = self::DEFAULT_MAX_ARGS,
        public readonly int $maxBodyBytes = self::DEFAULT_MAX_BODY_BYTES,
        public readonly int $maxArgBytes = self::DEFAULT_MAX_ARG_BYTES,
    ) {
        if ($paranoia < 1 || $paranoia > 4) {
            throw new ConfigurationException('Paranoia level must be between 1 and 4, got ' . $paranoia);
        }

        if (!in_array($mode, [self::MODE_BLOCK, self::MODE_MONITOR], true)) {
            throw new ConfigurationException(sprintf("Mode must be 'block' or 'monitor', got '%s'", $mode));
        }

        // Zero would mean "inspect nothing", which is a WAF that does not work.
        // UNLIMITED is spelled -1 so that reading the value cannot be confused
        // with an accidental 0 from an unset config key.
        $inspectionLimits = [
            'maxArgs'      => $maxArgs,
            'maxBodyBytes' => $maxBodyBytes,
            'maxArgBytes'  => $maxArgBytes,
        ];
        foreach ($inspectionLimits as $name => $limit) {
            if ($limit !== self::UNLIMITED && $limit < 1) {
                throw new ConfigurationException(sprintf(
                    '%s must be a positive integer or CrsConfig::UNLIMITED (%d), got %d.',
                    $name,
                    self::UNLIMITED,
                    $limit,
                ));
            }
        }

        $this->anomalyThresholds = $this->normaliseThresholds($anomalyThresholds);
        $this->severityScores    = $this->normaliseSeverityScores($severityScores);
    }

    /**
     * @param array<string, int> $thresholds
     * @return array<string, int>
     */
    private function normaliseThresholds(array $thresholds): array
    {
        $out = self::DEFAULT_THRESHOLDS;

        foreach ($thresholds as $key => $value) {
            $lower = strtolower((string) $key);

            if (isset(self::DEFAULT_THRESHOLDS[$lower])) {
                $out[$lower] = (int) $value;
                continue;
            }

            if (isset(self::THRESHOLD_ALIASES[$lower])) {
                @trigger_error(
                    sprintf(
                        "CrsConfig: anomaly threshold key '%s' is deprecated, use '%s'. It sets the %s threshold, not a per-severity one.",
                        $lower,
                        self::THRESHOLD_ALIASES[$lower],
                        self::THRESHOLD_ALIASES[$lower],
                    ),
                    E_USER_DEPRECATED,
                );
                $out[self::THRESHOLD_ALIASES[$lower]] = (int) $value;
                continue;
            }

            if (in_array($lower, self::THRESHOLD_IGNORED, true)) {
                @trigger_error(
                    sprintf("CrsConfig: anomaly threshold key '%s' has never had any effect and is ignored; see severityScores.", $lower),
                    E_USER_DEPRECATED,
                );
                continue;
            }

            throw new ConfigurationException(sprintf(
                "Unknown anomaly threshold key '%s'. Expected one of: %s.",
                (string) $key,
                implode(', ', array_keys(self::DEFAULT_THRESHOLDS)),
            ));
        }

        return $out;
    }

    /**
     * @param array<string, int> $scores
     * @return array<string, int>
     */
    private function normaliseSeverityScores(array $scores): array
    {
        $out = self::DEFAULT_SEVERITY_SCORES;

        foreach ($scores as $key => $value) {
            $lower = strtolower((string) $key);
            if (!isset(self::DEFAULT_SEVERITY_SCORES[$lower])) {
                throw new ConfigurationException(sprintf(
                    "Unknown severity '%s'. Expected one of: %s.",
                    (string) $key,
                    implode(', ', array_keys(self::DEFAULT_SEVERITY_SCORES)),
                ));
            }

            $out[$lower] = (int) $value;
        }

        return $out;
    }

    public function inboundThreshold(): int
    {
        return $this->anomalyThresholds[self::THRESHOLD_INBOUND];
    }

    public function outboundThreshold(): int
    {
        return $this->anomalyThresholds[self::THRESHOLD_OUTBOUND];
    }

    public function severityScore(string $severity): int
    {
        return $this->severityScores[strtolower($severity)] ?? 0;
    }

    /**
     * @param array{
     *     paranoia?: int,
     *     mode?: string,
     *     anomaly_thresholds?: array<string, int>,
     *     disabled_rules?: array<int, int|string>,
     *     disabled_categories?: array<int, string>,
     *     rules_path?: ?string,
     *     severity_scores?: array<string, int>,
     *     fail_closed_on_operator_error?: bool,
     *     max_args?: int,
     *     max_body_bytes?: int,
     *     max_arg_bytes?: int
     * } $config
     */
    public static function fromArray(array $config): self
    {
        return new self(
            paranoia:           $config['paranoia'] ?? 1,
            mode:               $config['mode'] ?? self::MODE_BLOCK,
            anomalyThresholds:  $config['anomaly_thresholds'] ?? self::DEFAULT_THRESHOLDS,
            disabledRules:      array_map(intval(...), $config['disabled_rules'] ?? []),
            disabledCategories: $config['disabled_categories'] ?? [],
            rulesPath:          $config['rules_path'] ?? null,
            severityScores:     $config['severity_scores'] ?? self::DEFAULT_SEVERITY_SCORES,
            failClosedOnOperatorError: $config['fail_closed_on_operator_error'] ?? false,
            maxArgs:            $config['max_args'] ?? self::DEFAULT_MAX_ARGS,
            maxBodyBytes:       $config['max_body_bytes'] ?? self::DEFAULT_MAX_BODY_BYTES,
            maxArgBytes:        $config['max_arg_bytes'] ?? self::DEFAULT_MAX_ARG_BYTES,
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

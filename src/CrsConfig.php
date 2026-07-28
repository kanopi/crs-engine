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
     * Request body bytes handed to the ruleset, matching ModSecurity's
     * SecRequestBodyNoFilesLimit default. Cost is roughly linear in this, and
     * the body is entirely attacker-controlled.
     */
    public const DEFAULT_MAX_REQUEST_BODY_BYTES = 131072;

    /**
     * Response body bytes handed to the ruleset, matching ModSecurity's
     * SecResponseBodyLimit default.
     *
     * Four times the request figure, because the two directions carry very
     * different traffic. A 128 KB request body is large; a 128 KB HTML page is
     * ordinary. Capping responses at the request limit meant the 165
     * response-phase rules stopped seeing anything past 128 KB of a normal
     * page — and leaked stack traces, SQL errors and debug dumps cluster in
     * exactly that tail, appended after the content or emitted in a footer.
     */
    public const DEFAULT_MAX_RESPONSE_BODY_BYTES = 524288;

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
     * Outbound defaults to monitor, not block.
     *
     * The outbound threshold is 4 and 59 of the 61 response rules that carry a
     * message are severity error or critical, worth 4 and 5. So a single match
     * blocks: there is no anomaly accumulation outbound the way there is
     * inbound, where a threshold of 5 gives a notice or warning somewhere to
     * land. One rule, one block.
     *
     * That is too sharp to have on by default for the traffic this engine sees.
     * 953110 matches PHP function names in output, so a documentation page
     * listing fopen and fwrite trips it; 952110 matches a Java stack trace, so
     * a tutorial showing one trips it. Three of seven ordinary pages in the
     * pre-1.0 sweep were blocked. And blocking a response is heavier than
     * blocking a request — the application has already done the work, and the
     * visitor gets an error instead of a page that was fine.
     *
     * Monitor still evaluates every RESPONSE-* rule and still fills in
     * matchedRules and totalScore. Sites that want outbound blocking opt in
     * with responseMode: MODE_BLOCK, ideally after reading their own logs.
     */
    public const DEFAULT_RESPONSE_MODE = self::MODE_MONITOR;

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

    /** Effective mode for evaluate(); $mode unless overridden. */
    public readonly string $requestMode;

    /** Effective mode for evaluateResponse(); $mode unless overridden. */
    public readonly string $responseMode;

    /**
     * @param int $paranoia Paranoia level 1-4. Rules tagged with a higher PL are skipped.
     * @param string $mode block | monitor. The default for both directions;
     *        $requestMode and $responseMode override it individually.
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
     * @param int $maxRequestBodyBytes How much of the request body to hand to
     *        the ruleset. CrsConfig::UNLIMITED to inspect all of it.
     * @param int $maxArgBytes Total bytes of argument values a single rule will
     *        inspect. Bounds the work a few very large arguments can buy, which
     *        $maxArgs alone does not. CrsConfig::UNLIMITED to inspect all of it.
     * @param int $maxResponseBodyBytes How much of the response body to hand to
     *        the ruleset. Separate from the request limit because the two
     *        directions carry different traffic — see the constants above.
     *        CrsConfig::UNLIMITED to inspect all of it.
     * @param string|null $requestMode Overrides $mode for evaluate(). Null to
     *        follow $mode.
     * @param string|null $responseMode Overrides the outbound mode. Null uses
     *        DEFAULT_RESPONSE_MODE (monitor) rather than $mode — see that
     *        constant for why outbound is not blocked by default. Pass
     *        MODE_BLOCK explicitly to reject leaking responses.
     *
     *        Blocking outbound is a much heavier action than blocking inbound:
     *        the application has already done its work, and rejecting the
     *        response means serving an error in place of a page that may well
     *        be fine. A CMS typically wants to reject attacks on the way in
     *        and only record leakage on the way out, which is
     *        mode: block + responseMode: monitor.
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
        public readonly int $maxRequestBodyBytes = self::DEFAULT_MAX_REQUEST_BODY_BYTES,
        public readonly int $maxArgBytes = self::DEFAULT_MAX_ARG_BYTES,
        public readonly int $maxResponseBodyBytes = self::DEFAULT_MAX_RESPONSE_BODY_BYTES,
        ?string $requestMode = null,
        ?string $responseMode = null,
    ) {
        if ($paranoia < 1 || $paranoia > 4) {
            throw new ConfigurationException('Paranoia level must be between 1 and 4, got ' . $paranoia);
        }

        foreach (['mode' => $mode, 'requestMode' => $requestMode, 'responseMode' => $responseMode] as $name => $candidate) {
            if ($candidate !== null && !in_array($candidate, [self::MODE_BLOCK, self::MODE_MONITOR], true)) {
                throw new ConfigurationException(sprintf("%s must be 'block' or 'monitor', got '%s'", $name, $candidate));
            }
        }

        $this->requestMode  = $requestMode ?? $mode;
        $this->responseMode = $responseMode ?? self::DEFAULT_RESPONSE_MODE;

        // Zero would mean "inspect nothing", which is a WAF that does not work.
        // UNLIMITED is spelled -1 so that reading the value cannot be confused
        // with an accidental 0 from an unset config key.
        $inspectionLimits = [
            'maxArgs'              => $maxArgs,
            'maxRequestBodyBytes'  => $maxRequestBodyBytes,
            'maxArgBytes'          => $maxArgBytes,
            'maxResponseBodyBytes' => $maxResponseBodyBytes,
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

    /** Inbound and outbound can run in different modes — see the constructor. */
    public function modeFor(bool $requestPhase): string
    {
        return $requestPhase ? $this->requestMode : $this->responseMode;
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
     *     max_request_body_bytes?: int,
     *     max_arg_bytes?: int,
     *     max_response_body_bytes?: int,
     *     max_body_bytes?: int,
     *     request_mode?: ?string,
     *     response_mode?: ?string
     * } $config
     */
    public static function fromArray(array $config): self
    {
        // `max_body_bytes` governed both directions, using a limit sized for
        // requests — see the constants. Honoured so existing config keeps
        // working, but it sets both, which is the shape that was wrong.
        $legacyBodyBytes = null;
        if (isset($config['max_body_bytes'])) {
            @trigger_error(
                "CrsConfig: 'max_body_bytes' is deprecated; it caps requests and responses together at a "
                . "request-sized limit. Use 'max_request_body_bytes' and 'max_response_body_bytes'.",
                E_USER_DEPRECATED,
            );
            $legacyBodyBytes = $config['max_body_bytes'];
        }

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
            maxRequestBodyBytes:  $config['max_request_body_bytes'] ?? $legacyBodyBytes ?? self::DEFAULT_MAX_REQUEST_BODY_BYTES,
            maxArgBytes:          $config['max_arg_bytes'] ?? self::DEFAULT_MAX_ARG_BYTES,
            maxResponseBodyBytes: $config['max_response_body_bytes'] ?? $legacyBodyBytes ?? self::DEFAULT_MAX_RESPONSE_BODY_BYTES,
            requestMode:          $config['request_mode'] ?? null,
            responseMode:         $config['response_mode'] ?? null,
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

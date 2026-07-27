<?php

declare(strict_types=1);

namespace Kanopi\Crs\Runtime;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsVerdict;
use Kanopi\Crs\Operators\OperatorInterface;
use Kanopi\Crs\Operators\OperatorMatch;
use Kanopi\Crs\Operators\OperatorRegistry;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Request\ResponseData;
use Kanopi\Crs\Transforms\TransformRegistry;
use Kanopi\Crs\Variables\VariableResolver;

final class RuleEvaluator
{
    /**
     * Actions that stop evaluation and block. `block` is deliberately absent:
     * in CRS it defers to SecDefaultAction, which is `pass` for detection
     * rules. Only the 949/959 blocking-evaluation rules carry `deny`.
     */
    private const DISRUPTIVE_ACTIONS = ['deny', 'drop'];

    /**
     * Engine-level accumulators and constants. They live in the same tx.*_score
     * namespace as the per-category counters but are not categories, so they
     * must not surface in CrsVerdict::$scores.
     */
    private const ANOMALY_ACCUMULATOR_MARKER = 'anomaly_score';

    public function __construct(
        private readonly OperatorRegistry $operatorRegistry,
        private readonly TransformRegistry $transformRegistry,
        private readonly CrsConfig $crsConfig,
    ) {
    }

    /**
     * Evaluate a ruleset against a request and produce a verdict.
     */
    public function evaluate(RuleSet $ruleSet, RequestData $requestData): CrsVerdict
    {
        return $this->run($ruleSet, $requestData, null, requestPhase: true);
    }

    /**
     * Evaluate response-phase (phase 3 + 4) rules against the response body
     * and headers. RESPONSE-* rules in CRS catch data leakage like SQL error
     * messages, stack traces, PHP warnings.
     */
    public function evaluateResponse(RuleSet $ruleSet, RequestData $requestData, ResponseData $responseData): CrsVerdict
    {
        return $this->run($ruleSet, $requestData, $responseData, requestPhase: false);
    }

    private function run(RuleSet $ruleSet, RequestData $requestData, ?ResponseData $responseData, bool $requestPhase): CrsVerdict
    {
        $txStore          = new TxStore();
        foreach (CrsTxDefaults::forConfig($this->crsConfig) as $name => $value) {
            $txStore->set($name, $value);
        }

        $variableResolver    = new VariableResolver(
            $txStore,
            $responseData,
            $this->crsConfig->maxArgs,
            $this->crsConfig->maxRequestBodyBytes,
            $this->crsConfig->maxArgBytes,
            $this->crsConfig->maxResponseBodyBytes,
        );
        $transformPipeline    = new TransformPipeline($this->transformRegistry);
        $matched     = [];
        $skipUntil   = null;
        $blockingId  = null;
        /** @var array<int, array{rule_id: int, operator: string, error: string}> $operatorErrors */
        $operatorErrors = [];

        foreach ($ruleSet->all() as $compiledRule) {
            // Markers are phase-agnostic and never evaluated — they exist only
            // to terminate a skip. Checked before the phase filter so a skip
            // started by a phase-1 rule can still land on the marker.
            if ($compiledRule->isMarker()) {
                if ($skipUntil !== null && $compiledRule->marker === $skipUntil) {
                    $skipUntil = null;
                }

                continue;
            }

            if ($requestPhase && $compiledRule->phase >= 3) {
                continue;
            }

            if (!$requestPhase && $compiledRule->phase < 3) {
                continue;
            }

            if ($skipUntil !== null) {
                if (in_array($skipUntil, $compiledRule->tags, true) || (string) $compiledRule->id === $skipUntil) {
                    $skipUntil = null;
                }

                continue;
            }

            if ($compiledRule->paranoia > $this->crsConfig->paranoia) {
                continue;
            }

            if ($this->crsConfig->isRuleDisabled($compiledRule->id)) {
                continue;
            }

            if ($this->crsConfig->isCategoryDisabled($compiledRule->category)) {
                continue;
            }

            // SecAction: no operator to test, applies to every request. Used by
            // CRS for score bookkeeping, so it must run — but it is not a
            // detection and does not belong in the matched-rule report.
            if ($compiledRule->isUnconditional()) {
                $this->applySetvars($compiledRule, $txStore);
                continue;
            }

            if (!$this->operatorRegistry->has($compiledRule->operator)) {
                continue;
            }

            $hit = $this->evaluateRule($compiledRule, $requestData, $variableResolver, $transformPipeline, $txStore, $operatorErrors);
            if (!$hit instanceof \Kanopi\Crs\Operators\OperatorMatch) {
                continue;
            }

            // Report detections, not control flow. CRS's paranoia gates, skip
            // rules and score aggregators match constantly and carry neither a
            // message nor an anomaly contribution; listing them buries the two
            // findings that matter under twenty that don't. Every rule in the
            // shipped ruleset that contributes score also has a message, so
            // this drops nothing real.
            $score = $this->scoreFromSetvars($compiledRule, $txStore);
            if ($compiledRule->message !== '' || $score !== 0) {
                $matched[] = [
                    'id'           => $compiledRule->id,
                    'msg'          => $compiledRule->message,
                    'severity'     => $compiledRule->severity,
                    'score'        => $score,
                    'tags'         => $compiledRule->tags,
                    'category'     => $compiledRule->category,
                    'matched_data' => $hit->matchedData,
                    'logdata'      => $compiledRule->logdata === null
                        ? null
                        : $this->expandVariableRefs($compiledRule->logdata, $txStore, $this->matchContext($hit)),
                ];
            }

            // Only `deny` and `drop` are disruptive. In CRS, `block` defers to
            // SecDefaultAction, which for the detection rules is `pass` — they
            // contribute anomaly score and nothing else. Treating `block` as
            // disruptive short-circuited on the first match, which bypassed
            // anomaly scoring entirely and made anomalyThresholds inert.
            // The 949/959 blocking-evaluation rules carry the real `deny`.
            if (in_array($compiledRule->action, self::DISRUPTIVE_ACTIONS, true) && $this->crsConfig->modeFor($requestPhase) === CrsConfig::MODE_BLOCK) {
                $blockingId = $compiledRule->id;
                break;
            }

            if ($compiledRule->skipAfter !== null) {
                $skipUntil = $compiledRule->skipAfter;
            }
        }

        $scores     = $this->scoresByCategory($txStore);
        $totalScore = $this->totalScore($txStore, $requestPhase);
        $action     = $this->decideAction($blockingId, $totalScore, $requestPhase, $operatorErrors);

        return new CrsVerdict(
            $action,
            $scores,
            $matched,
            $totalScore,
            $blockingId,
            $operatorErrors,
            $variableResolver->truncations(),
        );
    }

    /**
     * @param array<int, array{rule_id: int, operator: string, error: string}> $operatorErrors
     */
    private function evaluateRule(CompiledRule $compiledRule, RequestData $requestData, VariableResolver $variableResolver, TransformPipeline $transformPipeline, TxStore $txStore, array &$operatorErrors): ?OperatorMatch
    {
        $operator = $this->operatorRegistry->get($compiledRule->operator);
        $values   = $variableResolver->resolve($compiledRule->targets, $requestData);
        $operatorArg = $this->expandVariableRefs($compiledRule->operatorArgument, $txStore);
        // Once per rule, not once per resolved value.
        $transforms = $transformPipeline->resolve($compiledRule->transforms);

        foreach ($values as $value) {
            $match = $this->evaluateOperatorAgainstValue($compiledRule, $operator, $operatorArg, $value->value, $transformPipeline, $transforms);

            // The operator abandoned this value rather than deciding on it, so
            // the rule did not get to run. Record the gap and keep going: the
            // remaining values may still be decidable, and one awkward argument
            // should not stop the rest of the request being inspected.
            if ($match->isError()) {
                $operatorErrors[] = [
                    'rule_id'  => $compiledRule->id,
                    'operator' => $compiledRule->operator,
                    'error'    => (string) $match->error,
                ];
                continue;
            }

            if (!$match->matched) {
                continue;
            }

            $match = $match->withMatchedName($value->location);

            // ModSecurity runs a rule's non-disruptive actions when that rule
            // matches, not when the whole chain does. CRS depends on it: the
            // starter of 931130 writes tx.rfi_parameter_<name> and the chained
            // condition reads it straight back via a TX regex selector. So
            // captures and setvars are applied here, before descending.
            $this->applyCaptures($compiledRule, $match, $txStore);
            $this->applySetvars($compiledRule, $txStore, $match);

            if ($compiledRule->chain === []) {
                return $match;
            }

            foreach ($compiledRule->chain as $sub) {
                $subHit = $this->evaluateRule($sub, $requestData, $variableResolver, $transformPipeline, $txStore, $operatorErrors);
                if (!$subHit instanceof OperatorMatch) {
                    return null;
                }
            }

            return $match;
        }

        return null;
    }

    /**
     * Copy numbered regex groups into TX:0..TX:9, as ModSecurity's `capture`
     * action does. Without this, every %{TX.0} reference in the ruleset — in
     * a chained condition, a setvar name, or an operator argument — expanded
     * to an empty string.
     */
    private function applyCaptures(CompiledRule $compiledRule, OperatorMatch $operatorMatch, TxStore $txStore): void
    {
        if (!$compiledRule->capture) {
            return;
        }

        foreach ($operatorMatch->captures as $index => $group) {
            if ($index > 9) {
                break;
            }

            $txStore->set('tx.' . $index, $group);
        }
    }

    /**
     * Expand %{tx.foo} (and %{TX.FOO}) references in an operator argument
     * against the current TxStore. Unset references resolve to empty
     * string. Anomaly-score constants were already inlined at parse time
     * and won't have %{} markers left.
     */
    /**
     * @param array<string, string> $context Request-scoped pseudo-variables
     *        such as MATCHED_VAR_NAME, which live outside the TX store.
     */
    private function expandVariableRefs(string $argument, TxStore $txStore, array $context = []): string
    {
        if (!str_contains($argument, '%{')) {
            return $argument;
        }

        return (string) preg_replace_callback(
            '/%\{([^}]+)\}/',
            static function (array $m) use ($txStore, $context): string {
                $name = $m[1];

                $upper = strtoupper($name);
                if (isset($context[$upper])) {
                    return $context[$upper];
                }

                $value = $txStore->get($name);
                if ($value === null && !str_contains($name, '.')) {
                    $value = $txStore->get('tx.' . $name);
                }

                return $value ?? '';
            },
            $argument
        );
    }

    /**
     * @return array<string, string>
     */
    private function matchContext(?OperatorMatch $operatorMatch): array
    {
        if (!$operatorMatch instanceof OperatorMatch) {
            return [];
        }

        return [
            'MATCHED_VAR'      => $operatorMatch->matchedData,
            'MATCHED_VAR_NAME' => $operatorMatch->matchedName ?? '',
        ];
    }

    /**
     * Run the operator against a single resolved value. When the rule has
     * `multiMatch` set we re-evaluate after each transform step so payloads
     * that match a mid-pipeline normalisation (e.g. after t:urlDecode but
     * before t:htmlEntityDecode) still fire.
     */
    /**
     * @param array<int, \Kanopi\Crs\Transforms\TransformInterface> $transforms
     */
    private function evaluateOperatorAgainstValue(CompiledRule $compiledRule, OperatorInterface $operator, string $operatorArg, string $value, TransformPipeline $transformPipeline, array $transforms): OperatorMatch
    {
        if ($compiledRule->multiMatch) {
            $firstError = null;

            foreach ($transformPipeline->eachResolved($transforms, $value) as $candidate) {
                $match = $operator->evaluate($operatorArg, $candidate);

                // One pipeline step being undecidable does not make the others
                // so — a payload that blows the backtrack limit before
                // t:removeComments may well be decidable after it. Keep the
                // first failure in case nothing later matches.
                if ($match->isError()) {
                    $firstError ??= $match;
                    continue;
                }

                if ($compiledRule->operatorNegated) {
                    $match = $match->matched ? OperatorMatch::miss() : OperatorMatch::hit($candidate);
                }

                if ($match->matched) {
                    return $match;
                }
            }

            return $firstError ?? OperatorMatch::miss();
        }

        $transformed = $transformPipeline->applyResolved($transforms, $value);
        $match = $operator->evaluate($operatorArg, $transformed);

        // Negation must not be applied to an error. "Could not look" inverted
        // becomes "definitely matched", which on a `!@rx` rule would turn an
        // abandoned regex into a positive detection carrying anomaly score —
        // trading a silent false negative for a loud false positive.
        if ($match->isError()) {
            return $match;
        }

        if ($compiledRule->operatorNegated) {
            return $match->matched ? OperatorMatch::miss() : OperatorMatch::hit($transformed);
        }

        return $match;
    }

    private function applySetvars(CompiledRule $compiledRule, TxStore $txStore, ?OperatorMatch $operatorMatch = null): void
    {
        $context = $this->matchContext($operatorMatch);

        foreach ($compiledRule->setvars as $sv) {
            // Names are templates too. CRS builds per-parameter counters with
            // setvar:'tx.paramcounter_%{MATCHED_VAR_NAME}=+1', which without
            // expansion all collapsed onto one literal key and made the
            // HTTP-parameter-pollution rules meaningless.
            $name  = $this->expandVariableRefs($sv['name'], $txStore, $context);
            $op    = $sv['op'];
            // Right-hand sides carry live references — CRS aggregates with
            // setvar:'tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl1}'
            // — so they have to be expanded per request, not at parse time.
            $value = $this->expandVariableRefs($sv['value'], $txStore, $context);
            switch ($op) {
                case '=':
                    $txStore->set($name, $value);
                    break;
                case '+':
                    $txStore->increment($name, (int) $value);
                    break;
                case '-':
                    $txStore->decrement($name, (int) $value);
                    break;
                case 'unset':
                    $txStore->unset($name);
                    break;
            }
        }
    }

    /**
     * What this rule contributed to the anomaly total.
     *
     * A CRS rule increments two counters with the same value — its category
     * counter and the paranoia-level anomaly bucket — so summing everything
     * matching `_score` reported double the real contribution. Count the
     * anomaly bucket only; the category counters are reported via $scores.
     */
    private function scoreFromSetvars(CompiledRule $compiledRule, TxStore $txStore): int
    {
        $score = 0;

        // CRS puts the anomaly setvar on the last link of a chain, so a
        // chained rule's contribution lives in its children, not its starter.
        foreach ($compiledRule->chain as $sub) {
            $score += $this->scoreFromSetvars($sub, $txStore);
        }

        foreach ($compiledRule->setvars as $sv) {
            if ($sv['op'] !== '+') {
                continue;
            }

            // Only the per-paranoia-level bucket. The 949/959 rules aggregate
            // those buckets into blocking_*/detection_* totals; counting those
            // too would report the running total as if the rule contributed it.
            if (!preg_match('/_anomaly_score_pl\d+$/', strtolower($sv['name']))) {
                continue;
            }

            $score += (int) $this->expandVariableRefs($sv['value'], $txStore);
        }

        return $score;
    }

    /**
     * Per-attack-category scores (sql_injection, xss, rce, ...). Everything in
     * the tx.*anomaly_score* family is an engine accumulator or a severity
     * constant, not a category, and is reported via $totalScore instead.
     *
     * @return array<string, int>
     */
    private function scoresByCategory(TxStore $txStore): array
    {
        $out = [];
        foreach ($txStore->all() as $key => $value) {
            $clean = preg_replace('/^tx\./', '', $key) ?? $key;
            if (str_contains($clean, self::ANOMALY_ACCUMULATOR_MARKER)) {
                continue;
            }

            if (preg_match('/^(.+)_score$/', $clean, $m)) {
                $out[$m[1]] = (int) $value;
            }
        }

        return $out;
    }

    /**
     * The anomaly total for the phase just evaluated.
     *
     * CRS aggregates the per-paranoia-level buckets into
     * tx.blocking_{inbound,outbound}_anomaly_score in its 949/959 rules. Prefer
     * that, and fall back to summing the buckets directly so a custom ruleset
     * without the 949/959 series still reports a total.
     */
    private function totalScore(TxStore $txStore, bool $requestPhase): int
    {
        $direction = $requestPhase ? 'inbound' : 'outbound';

        // 1. What CRS 4 produces: the 949/959 rules aggregate the buckets into
        //    tx.blocking_<direction>_anomaly_score.
        $aggregate = (int) ($txStore->get('tx.blocking_' . $direction . '_anomaly_score') ?? '0');
        if ($aggregate > 0) {
            return $aggregate;
        }

        // 2. A ruleset carrying the per-paranoia-level buckets but not the
        //    949/959 aggregation rules.
        $buckets = 0;
        foreach ($txStore->all() as $key => $value) {
            $clean = preg_replace('/^tx\./', '', $key) ?? $key;
            if (preg_match('/^' . $direction . '_anomaly_score_pl\d+$/', $clean)) {
                $buckets += (int) $value;
            }
        }

        if ($buckets > 0) {
            return $buckets;
        }

        // 3. A ruleset that accumulates straight into the undivided counter.
        return (int) ($txStore->get('tx.' . $direction . '_anomaly_score') ?? '0');
    }

    /** Inbound and outbound have separate thresholds in CRS. */
    private function thresholdFor(bool $requestPhase): int
    {
        return $requestPhase
            ? $this->crsConfig->inboundThreshold()
            : $this->crsConfig->outboundThreshold();
    }

    /**
     * @param array<int, array{rule_id: int, operator: string, error: string}> $operatorErrors
     */
    private function decideAction(?int $blockingId, int $totalScore, bool $requestPhase, array $operatorErrors): string
    {
        if ($blockingId !== null && $this->crsConfig->modeFor($requestPhase) === CrsConfig::MODE_BLOCK) {
            return CrsVerdict::ACTION_BLOCK;
        }

        // Opt-in: a request that could not be fully inspected is not one we can
        // call clean. Off by default because enabling it can reject traffic
        // that previously passed, and the operator errors are on the verdict
        // either way — so an integrator can measure how often this fires before
        // deciding to act on it.
        if ($operatorErrors !== [] && $this->crsConfig->failClosedOnOperatorError) {
            return $this->crsConfig->modeFor($requestPhase) === CrsConfig::MODE_BLOCK
                ? CrsVerdict::ACTION_BLOCK
                : CrsVerdict::ACTION_LOG;
        }

        if ($totalScore >= $this->thresholdFor($requestPhase)) {
            return $this->crsConfig->modeFor($requestPhase) === CrsConfig::MODE_BLOCK
                ? CrsVerdict::ACTION_BLOCK
                : CrsVerdict::ACTION_LOG;
        }

        return $totalScore > 0 ? CrsVerdict::ACTION_LOG : CrsVerdict::ACTION_ALLOW;
    }
}

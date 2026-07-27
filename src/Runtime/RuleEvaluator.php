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

        $variableResolver    = new VariableResolver($txStore, $responseData);
        $transformPipeline    = new TransformPipeline($this->transformRegistry);
        $matched     = [];
        $skipUntil   = null;
        $blockingId  = null;

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

            $hit = $this->evaluateRule($compiledRule, $requestData, $variableResolver, $transformPipeline, $txStore);
            if (!$hit instanceof \Kanopi\Crs\Operators\OperatorMatch) {
                continue;
            }

            $this->applySetvars($compiledRule, $txStore);

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
                ];
            }

            // Only `deny` and `drop` are disruptive. In CRS, `block` defers to
            // SecDefaultAction, which for the detection rules is `pass` — they
            // contribute anomaly score and nothing else. Treating `block` as
            // disruptive short-circuited on the first match, which bypassed
            // anomaly scoring entirely and made anomalyThresholds inert.
            // The 949/959 blocking-evaluation rules carry the real `deny`.
            if (in_array($compiledRule->action, self::DISRUPTIVE_ACTIONS, true) && $this->crsConfig->mode === CrsConfig::MODE_BLOCK) {
                $blockingId = $compiledRule->id;
                break;
            }

            if ($compiledRule->skipAfter !== null) {
                $skipUntil = $compiledRule->skipAfter;
            }
        }

        $scores     = $this->scoresByCategory($txStore);
        $totalScore = $this->totalScore($txStore, $requestPhase);
        $action     = $this->decideAction($blockingId, $totalScore, $requestPhase);

        return new CrsVerdict($action, $scores, $matched, $totalScore, $blockingId);
    }

    private function evaluateRule(CompiledRule $compiledRule, RequestData $requestData, VariableResolver $variableResolver, TransformPipeline $transformPipeline, TxStore $txStore): ?OperatorMatch
    {
        $operator = $this->operatorRegistry->get($compiledRule->operator);
        $values   = $variableResolver->resolve($compiledRule->targets, $requestData);
        $operatorArg = $this->expandVariableRefs($compiledRule->operatorArgument, $txStore);

        foreach ($values as $value) {
            $match = $this->evaluateOperatorAgainstValue($compiledRule, $operator, $operatorArg, $value->value, $transformPipeline);
            if (!$match->matched) {
                continue;
            }

            if ($compiledRule->chain === []) {
                return $match;
            }

            foreach ($compiledRule->chain as $sub) {
                $subHit = $this->evaluateRule($sub, $requestData, $variableResolver, $transformPipeline, $txStore);
                if (!$subHit instanceof OperatorMatch) {
                    return null;
                }
            }

            return $match;
        }

        return null;
    }

    /**
     * Expand %{tx.foo} (and %{TX.FOO}) references in an operator argument
     * against the current TxStore. Unset references resolve to empty
     * string. Anomaly-score constants were already inlined at parse time
     * and won't have %{} markers left.
     */
    private function expandVariableRefs(string $argument, TxStore $txStore): string
    {
        if (!str_contains($argument, '%{')) {
            return $argument;
        }

        return (string) preg_replace_callback(
            '/%\{([^}]+)\}/',
            static function (array $m) use ($txStore): string {
                $name = $m[1];
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
     * Run the operator against a single resolved value. When the rule has
     * `multiMatch` set we re-evaluate after each transform step so payloads
     * that match a mid-pipeline normalisation (e.g. after t:urlDecode but
     * before t:htmlEntityDecode) still fire.
     */
    private function evaluateOperatorAgainstValue(CompiledRule $compiledRule, OperatorInterface $operator, string $operatorArg, string $value, TransformPipeline $transformPipeline): OperatorMatch
    {
        if ($compiledRule->multiMatch) {
            foreach ($transformPipeline->each($compiledRule->transforms, $value) as $candidate) {
                $match = $operator->evaluate($operatorArg, $candidate);
                if ($compiledRule->operatorNegated) {
                    $match = $match->matched ? OperatorMatch::miss() : OperatorMatch::hit($candidate);
                }

                if ($match->matched) {
                    return $match;
                }
            }

            return OperatorMatch::miss();
        }

        $transformed = $transformPipeline->apply($compiledRule->transforms, $value);
        $match = $operator->evaluate($operatorArg, $transformed);
        if ($compiledRule->operatorNegated) {
            return $match->matched ? OperatorMatch::miss() : OperatorMatch::hit($transformed);
        }

        return $match;
    }

    private function applySetvars(CompiledRule $compiledRule, TxStore $txStore): void
    {
        foreach ($compiledRule->setvars as $sv) {
            $name  = $sv['name'];
            $op    = $sv['op'];
            // Right-hand sides carry live references — CRS aggregates with
            // setvar:'tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl1}'
            // — so they have to be expanded per request, not at parse time.
            $value = $this->expandVariableRefs($sv['value'], $txStore);
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

    /**
     * Inbound and outbound have separate thresholds in CRS. The config keys are
     * still named by severity — see #14 — so map them here rather than at the
     * call site.
     */
    private function thresholdFor(bool $requestPhase): int
    {
        $key = $requestPhase ? 'critical' : 'error';
        return $this->crsConfig->anomalyThresholds[$key] ?? PHP_INT_MAX;
    }

    private function decideAction(?int $blockingId, int $totalScore, bool $requestPhase): string
    {
        if ($blockingId !== null && $this->crsConfig->mode === CrsConfig::MODE_BLOCK) {
            return CrsVerdict::ACTION_BLOCK;
        }

        if ($totalScore >= $this->thresholdFor($requestPhase)) {
            return $this->crsConfig->mode === CrsConfig::MODE_BLOCK
                ? CrsVerdict::ACTION_BLOCK
                : CrsVerdict::ACTION_LOG;
        }

        return $totalScore > 0 ? CrsVerdict::ACTION_LOG : CrsVerdict::ACTION_ALLOW;
    }
}

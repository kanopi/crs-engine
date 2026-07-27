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

            if (!$this->operatorRegistry->has($compiledRule->operator)) {
                continue;
            }

            $hit = $this->evaluateRule($compiledRule, $requestData, $variableResolver, $transformPipeline, $txStore);
            if (!$hit instanceof \Kanopi\Crs\Operators\OperatorMatch) {
                continue;
            }

            $this->applySetvars($compiledRule, $txStore);

            $matched[] = [
                'id'           => $compiledRule->id,
                'msg'          => $compiledRule->message,
                'severity'     => $compiledRule->severity,
                'score'        => $this->scoreFromSetvars($compiledRule),
                'tags'         => $compiledRule->tags,
                'category'     => $compiledRule->category,
                'matched_data' => $hit->matchedData,
            ];

            if ((in_array($compiledRule->action, ['deny', 'block', 'drop'], true)) && $this->crsConfig->mode === CrsConfig::MODE_BLOCK) {
                $blockingId = $compiledRule->id;
                break;
            }

            if ($compiledRule->skipAfter !== null) {
                $skipUntil = $compiledRule->skipAfter;
            }
        }

        $scores     = $this->scoresByCategory($txStore);
        $totalScore = $this->totalScore($txStore);
        $action     = $this->decideAction($blockingId, $totalScore);

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
            $value = $sv['value'];
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

    private function scoreFromSetvars(CompiledRule $compiledRule): int
    {
        $score = 0;
        foreach ($compiledRule->setvars as $sv) {
            if ($sv['op'] !== '+') {
                continue;
            }

            if (!str_contains($sv['name'], '_score')) {
                continue;
            }

            $score += (int) $sv['value'];
        }

        return $score;
    }

    /**
     * @return array<string, int>
     */
    private function scoresByCategory(TxStore $txStore): array
    {
        $out = [];
        foreach ($txStore->all() as $key => $value) {
            $clean = preg_replace('/^tx\./', '', $key) ?? $key;
            // Skip CRS seed defaults so they don't masquerade as categories.
            if (in_array($clean, ['critical_anomaly_score', 'error_anomaly_score', 'warning_anomaly_score', 'notice_anomaly_score', 'inbound_anomaly_score_threshold', 'outbound_anomaly_score_threshold'], true)) {
                continue;
            }

            if (preg_match('/^inbound_anomaly_score(?:_pl\d+)?$/', $clean)) {
                continue;
            }

            if (preg_match('/^outbound_anomaly_score$/', $clean)) {
                continue;
            }

            if (preg_match('/^(.+)_score$/', $clean, $m)) {
                $out[$m[1]] = (int) $value;
            }
        }

        return $out;
    }

    private function totalScore(TxStore $txStore): int
    {
        $total = 0;
        foreach ($txStore->all() as $key => $value) {
            $clean = preg_replace('/^tx\./', '', $key) ?? $key;
            if (preg_match('/^inbound_anomaly_score_pl\d+$/', $clean)) {
                $total += (int) $value;
            }
        }

        return $total;
    }

    private function decideAction(?int $blockingId, int $totalScore): string
    {
        if ($blockingId !== null && $this->crsConfig->mode === CrsConfig::MODE_BLOCK) {
            return CrsVerdict::ACTION_BLOCK;
        }

        $threshold = $this->crsConfig->anomalyThresholds['critical'] ?? PHP_INT_MAX;
        if ($totalScore >= $threshold) {
            return $this->crsConfig->mode === CrsConfig::MODE_BLOCK
                ? CrsVerdict::ACTION_BLOCK
                : CrsVerdict::ACTION_LOG;
        }

        return $totalScore > 0 ? CrsVerdict::ACTION_LOG : CrsVerdict::ACTION_ALLOW;
    }
}

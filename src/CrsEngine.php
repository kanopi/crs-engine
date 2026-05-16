<?php

declare(strict_types=1);

namespace Kanopi\Crs;

use Kanopi\Crs\Operators\OperatorRegistry;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Request\ResponseData;
use Kanopi\Crs\Runtime\RuleEvaluator;
use Kanopi\Crs\Runtime\RuleSet;
use Kanopi\Crs\Transforms\TransformRegistry;

/**
 * Public entry point. Construct once per process (rules load is expensive),
 * call evaluate() per request.
 */
final class CrsEngine
{
    private readonly RuleSet $ruleSet;

    public function __construct(
        private readonly CrsConfig $crsConfig,
        ?RuleSet $ruleSet = null,
        private readonly ?OperatorRegistry $operatorRegistry = null,
        private readonly ?TransformRegistry $transformRegistry = null,
    ) {
        $this->ruleSet = $ruleSet ?? RuleSet::loadFromDirectory(
            $crsConfig->rulesPath ?? dirname(__DIR__) . '/rules'
        );
    }

    public function evaluate(RequestData $requestData): CrsVerdict
    {
        return $this->makeEvaluator()->evaluate($this->ruleSet, $requestData);
    }

    /**
     * Run RESPONSE-* rules against the response the application generated.
     * Call AFTER evaluate() returned non-block and the response has been
     * rendered — these rules detect data leakage (SQL errors, stack traces,
     * PHP warnings) in what would otherwise be sent to the client.
     */
    public function evaluateResponse(RequestData $requestData, ResponseData $responseData): CrsVerdict
    {
        return $this->makeEvaluator()->evaluateResponse($this->ruleSet, $requestData, $responseData);
    }

    private function makeEvaluator(): RuleEvaluator
    {
        $operators  = $this->operatorRegistry  ?? new OperatorRegistry();
        $transforms = $this->transformRegistry ?? new TransformRegistry();
        return new RuleEvaluator($operators, $transforms, $this->crsConfig);
    }

    public function ruleCount(): int
    {
        return $this->ruleSet->count();
    }

    public function crsVersion(): string
    {
        return $this->ruleSet->crsVersion();
    }

    public function ruleSet(): RuleSet
    {
        return $this->ruleSet;
    }
}

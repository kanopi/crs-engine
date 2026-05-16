<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Runtime;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\Parser\SecLangParser;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Runtime\CompiledRule;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

/**
 * multiMatch should re-evaluate the operator after each transform step so
 * an attack that becomes visible only at a mid-pipeline normalisation
 * still fires the rule.
 */
final class MultiMatchTest extends TestCase
{
    public function testMultiMatchFindsMidPipelineMatch(): void
    {
        $compiledRule = $this->buildRule(
            // Looks for "<script" — only visible AFTER urlDecode, not after
            // the final htmlEntityDecode step. Without multiMatch the rule
            // would miss because the pipeline ends in a non-canonical state.
            operatorArg: '<script',
            transforms:  ['none', 'urlDecode', 'htmlEntityDecode'],
            multiMatch:  true,
        );

        $crsEngine = new CrsEngine(new CrsConfig(), new RuleSet([$compiledRule], 'test'));
        $crsVerdict = $crsEngine->evaluate($this->requestArg('html', '%3Cscript%3E'));
        $this->assertTrue($crsVerdict->isBlocked(), 'multiMatch should catch the URL-decoded form');
    }

    public function testWithoutMultiMatchOnlyFinalValueIsChecked(): void
    {
        // Without multiMatch, an operator searching for the un-lowered form
        // misses because the pipeline always lowercases first.
        $compiledRule = $this->buildRule(
            operatorArg: 'SELECT',
            transforms:  ['lowercase'],
            multiMatch:  false,
        );
        $crsEngine = new CrsEngine(new CrsConfig(), new RuleSet([$compiledRule], 'test'));
        $crsVerdict = $crsEngine->evaluate($this->requestArg('q', 'SELECT * FROM users'));
        $this->assertFalse($crsVerdict->isBlocked());
    }

    public function testMultiMatchCatchesPreTransformMatch(): void
    {
        $compiledRule = $this->buildRule(
            operatorArg: 'SELECT',
            transforms:  ['lowercase'],
            multiMatch:  true,
        );
        $crsEngine = new CrsEngine(new CrsConfig(), new RuleSet([$compiledRule], 'test'));
        $crsVerdict = $crsEngine->evaluate($this->requestArg('q', 'SELECT * FROM users'));
        $this->assertTrue($crsVerdict->isBlocked(), 'multiMatch should match the original un-lowered value');
    }

    private function buildRule(string $operatorArg, array $transforms, bool $multiMatch): CompiledRule
    {
        $multi = $multiMatch ? 'multiMatch,' : '';
        $conf = <<<CONF
SecRule ARGS "@rx {$operatorArg}" "id:9001,phase:2,block,{$multi}\
    t:none,setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
CONF;

        $secLangParser = new SecLangParser();
        $parsed = $secLangParser->parseString($conf);
        $rule = $parsed[0];

        // Override transforms with what the test wants
        return CompiledRule::fromArray(array_merge($rule->toArray(), [
            'transforms' => $transforms,
            'multi_match' => $multiMatch,
        ]));
    }

    private function requestArg(string $name, string $value): RequestData
    {
        $qs = $name . '=' . urlencode($value);
        return new RequestData(
            method: 'GET',
            uri: '/?' . $qs,
            rawUri: '/?' . $qs,
            queryString: $qs,
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            queryArgs: [$name => $value],
        );
    }
}

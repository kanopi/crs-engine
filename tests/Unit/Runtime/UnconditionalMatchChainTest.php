<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Runtime;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\Parser\ParsedRule;
use Kanopi\Crs\Parser\SecLangParser;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Runtime\CompiledRule;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

/**
 * CRS 4.30 rewrote 922100 as a three-link chain whose middle link is
 * `@unconditionalMatch`: it exists only to copy each _charset_ value into its
 * own TX variable, which the last link then checks with a regex TX target.
 *
 * The real rule opens with `&MULTIPART_PART_HEADERS:_charset_`, which this
 * engine cannot satisfy (part headers are indexed by position, not part name),
 * so this drives the same chain from `&ARGS:_charset_` instead. What is under
 * test is the chain mechanics, not the multipart variable.
 */
final class UnconditionalMatchChainTest extends TestCase
{
    private const CONF = <<<'CONF'
SecRule &ARGS:_charset_ "@gt 0" \
    "id:922160,phase:2,pass,t:none,nolog,setvar:'tx.multipart_headers_charset_counter=0'"

SecRule &ARGS:_charset_ "!@eq 0" \
    "id:922100,phase:2,block,t:none,severity:'CRITICAL',chain"
    SecRule ARGS:_charset_ "@unconditionalMatch" \
        "setvar:'tx.922100_charset_%{tx.multipart_headers_charset_counter}=|%{MATCHED_VAR}|',\
        setvar:'tx.multipart_headers_charset_counter=+1',\
        chain"
        SecRule TX:/^922100_charset_/ "!@within %{tx.allowed_request_content_type_charset}" \
            "t:lowercase,\
            setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
CONF;

    public function testParsesWithoutDroppingTheRule(): void
    {
        $secLangParser = new SecLangParser();
        $parsed = $secLangParser->parseString(self::CONF);

        $this->assertSame([922160, 922100], array_map(static fn (ParsedRule $parsedRule): int => $parsedRule->id, $parsed));
        $this->assertSame([], $secLangParser->warnings);
    }

    public function testAllowedCharsetDoesNotFire(): void
    {
        $this->assertNotContains(922100, $this->matchedIds('utf-8'));
    }

    public function testDisallowedCharsetFires(): void
    {
        $this->assertContains(922100, $this->matchedIds('ibm037'));
    }

    /**
     * @return array<int, int>
     */
    private function matchedIds(string $charset): array
    {
        $rules = array_map(
            static fn (ParsedRule $parsedRule): CompiledRule => CompiledRule::fromArray($parsedRule->toArray()),
            (new SecLangParser())->parseString(self::CONF),
        );

        $crsEngine = new CrsEngine(new CrsConfig(), new RuleSet($rules, 'test'));
        $crsVerdict = $crsEngine->evaluate(new RequestData(
            method: 'POST',
            uri: '/upload',
            rawUri: '/upload',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            postArgs: ['_charset_' => $charset],
        ));

        return array_column($crsVerdict->matchedRules, 'id');
    }
}

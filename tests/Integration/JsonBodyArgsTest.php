<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\CrsVerdict;
use Kanopi\Crs\Request\RequestData;
use PHPUnit\Framework\TestCase;

/**
 * A JSON body has to reach ARGS, because that is where the ruleset looks.
 *
 * 187 CRS rules target ARGS; 19 target REQUEST_BODY; none target ARGS_POST.
 * Before the body was flattened, one of seven attack payloads in a JSON body was
 * blocked. All seven are now, matching what the same payloads score when the
 * integrator decodes the body themselves and what they score in an XML body,
 * which the engine has always parsed.
 */
final class JsonBodyArgsTest extends TestCase
{
    private CrsEngine $crsEngine;

    protected function setUp(): void
    {
        $this->crsEngine = new CrsEngine(new CrsConfig(paranoia: 1));
    }

    /**
     * @param array<string, string> $postArgs
     */
    private function verdict(string $body, array $postArgs = [], string $contentType = 'application/json', ?CrsConfig $crsConfig = null): CrsVerdict
    {
        $engine = $crsConfig instanceof CrsConfig ? new CrsEngine($crsConfig) : $this->crsEngine;

        return $engine->evaluate(new RequestData(
            method: 'POST',
            uri: '/api/items',
            rawUri: '/api/items',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            postArgs: $postArgs,
            headers: [
                'host'           => 'api.example.test',
                'content-type'   => $contentType,
                'content-length' => (string) strlen($body),
            ],
            body: $body,
        ));
    }

    /**
     * @return \Iterator<string, array{string}>
     */
    public static function attackProvider(): \Iterator
    {
        yield 'sqli union' => ["1' UNION ALL SELECT 1,2,3,4 -- "];
        yield 'sqli tautology' => ["' OR 1=1 -- "];
        yield 'xss script tag' => ['<script>alert(1)</script>'];
        yield 'xss event handler' => ['<img src=x onerror=alert(1)>'];
        yield 'lfi traversal' => ['../../etc/passwd'];
        yield 'rce shell' => ['; cat /etc/passwd'];
        yield 'php injection' => ['<?php system($_GET[0]); ?>'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('attackProvider')]
    public function testAnAttackInAJsonBodyIsDetectedWithNoHelpFromTheIntegrator(string $payload): void
    {
        $crsVerdict = $this->verdict((string) json_encode(['q' => $payload]));

        $this->assertTrue($crsVerdict->isBlocked(), 'The ruleset looks at ARGS; the body has to get there.');
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('attackProvider')]
    public function testParsingAgreesWithAnIntegratorSuppliedDecode(string $payload): void
    {
        $body = (string) json_encode(['q' => $payload]);

        $this->assertSame(
            $this->verdict($body, ['q' => $payload])->totalScore,
            $this->verdict($body)->totalScore,
            'Whether the integrator decoded the body should not change the verdict.'
        );
    }

    public function testAttacksNestedDeepInTheDocumentAreFound(): void
    {
        $body = (string) json_encode([
            'meta' => ['page' => 2],
            'filters' => [['field' => 'name', 'value' => "' OR 1=1 -- "]],
        ]);

        $this->assertTrue($this->verdict($body)->isBlocked());
    }

    /**
     * The differential guard. An integrator who supplied postArgs parsed the body
     * with the parser the application will use; re-parsing here would give two
     * readings of one document and let the attacker choose which one the WAF
     * inspects. So theirs wins outright for ARGS.
     *
     * Asserted on ARGS rather than on the verdict, because the verdict cannot
     * show it: REQUEST_BODY is inspected as raw text regardless — 19 rules
     * target it — so a payload in the body is still caught, which is correct and
     * unrelated to what ARGS contains.
     */
    public function testSuppliedArgsAreNotSupplementedByReparsingTheBody(): void
    {
        $requestData = new RequestData(
            method: 'POST',
            uri: '/api/items',
            rawUri: '/api/items',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            postArgs: ['q' => 'harmless'],
            headers: ['host' => 'x', 'content-type' => 'application/json'],
            body: '{"q":"injected"}',
        );

        $names = array_map(
            static fn (\Kanopi\Crs\Variables\ResolvedValue $resolvedValue): string => $resolvedValue->value,
            (new \Kanopi\Crs\Variables\VariableResolver(new \Kanopi\Crs\Runtime\TxStore()))
                ->resolve([['collection' => 'ARGS_NAMES']], $requestData),
        );

        $this->assertSame(['q'], $names, 'postArgs is authoritative; the body must not be parsed alongside it.');

        $values = array_map(
            static fn (\Kanopi\Crs\Variables\ResolvedValue $resolvedValue): string => $resolvedValue->value,
            (new \Kanopi\Crs\Variables\VariableResolver(new \Kanopi\Crs\Runtime\TxStore()))
                ->resolve([['collection' => 'ARGS']], $requestData),
        );

        $this->assertSame(['harmless'], $values);
    }

    public function testTheBodyIsParsedIntoArgsOnlyWhenNothingElseSuppliedThem(): void
    {
        $requestData = new RequestData(
            method: 'POST',
            uri: '/api/items',
            rawUri: '/api/items',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            headers: ['host' => 'x', 'content-type' => 'application/json'],
            body: '{"q":"injected"}',
        );

        $names = array_map(
            static fn (\Kanopi\Crs\Variables\ResolvedValue $resolvedValue): string => $resolvedValue->value,
            (new \Kanopi\Crs\Variables\VariableResolver(new \Kanopi\Crs\Runtime\TxStore()))
                ->resolve([['collection' => 'ARGS_NAMES']], $requestData),
        );

        $this->assertSame(['json.q'], $names);
    }

    public function testArgsAreNotDoubleCountedWhenTheIntegratorDecodes(): void
    {
        $args = ['a' => '1', 'b' => '2'];
        $body = (string) json_encode($args);

        $crsVerdict = $this->crsEngine->evaluate(new RequestData(
            method: 'POST',
            uri: '/api/items',
            rawUri: '/api/items',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            postArgs: $args,
            headers: ['host' => 'x', 'content-type' => 'application/json', 'content-length' => (string) strlen($body)],
            body: $body,
        ));

        // &ARGS feeds CRS 920380. Counting each argument twice would drag every
        // JSON request toward the max-args rule.
        $this->assertFalse($crsVerdict->isBlocked());
        $this->assertNotContains(920380, array_column($crsVerdict->matchedRules, 'id'));
    }

    public function testAnOrdinaryJsonApiRequestStillPasses(): void
    {
        $body = (string) json_encode([
            'name' => 'José García',
            'note' => 'Café ☕ très bien',
            'qty'  => 3,
            'tags' => ['blue', 'large'],
        ]);

        $crsVerdict = $this->verdict($body);

        $this->assertFalse($crsVerdict->isBlocked(), 'Flattening must not turn ordinary payloads into findings.');
        $this->assertSame(0, $crsVerdict->totalScore);
    }

    public function testAFormBodyIsUnaffected(): void
    {
        $crsVerdict = $this->verdict('a=1&b=2', [], 'application/x-www-form-urlencoded');

        $this->assertFalse($crsVerdict->isBlocked());
    }

    public function testAMalformedJsonBodyIsReportedAsACoverageGap(): void
    {
        $crsVerdict = $this->verdict('{"q":"unterminated');

        $this->assertTrue($crsVerdict->wasTruncated(), 'Nothing reached ARGS; that is worth saying.');
        $this->assertSame('json_body_unparsable', $crsVerdict->truncations[0]['what']);
    }

    public function testAnOversizedJsonBodyIsReportedRatherThanParsedTruncated(): void
    {
        $body = (string) json_encode(['q' => str_repeat('a', 400)]);
        $crsConfig = new CrsConfig(paranoia: 1, maxRequestBodyBytes: 100);

        $crsVerdict = $this->verdict($body, [], 'application/json', $crsConfig);

        $this->assertTrue($crsVerdict->wasTruncated());
        $this->assertContains(
            'body_too_large_to_parse',
            array_column($crsVerdict->truncations, 'what'),
            'A refused body should be distinguishable from a malformed one.'
        );
    }

    public function testTheArgumentCapsStillApplyToJsonArgs(): void
    {
        $wide = [];
        for ($i = 0; $i < 400; $i++) {
            $wide['k' . $i] = 'v' . $i;
        }

        $crsVerdict = $this->verdict((string) json_encode($wide));

        $this->assertTrue($crsVerdict->wasTruncated(), 'JSON args are args; the caps apply to them too.');
        $this->assertContains('args', array_column($crsVerdict->truncations, 'what'));
    }

    public function testCountingSeesTheJsonArgsSoTooManyArgumentsStillFires(): void
    {
        $wide = [];
        for ($i = 0; $i < 400; $i++) {
            $wide['k' . $i] = 'v';
        }

        $crsVerdict = $this->verdict((string) json_encode($wide));

        $this->assertContains(
            920380,
            array_column($crsVerdict->matchedRules, 'id'),
            'An over-large JSON document should trip the same rule an over-large form does.'
        );
    }
}

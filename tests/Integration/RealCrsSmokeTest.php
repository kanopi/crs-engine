<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Request\ResponseData;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end smoke tests against the bundled, real-CRS ruleset.
 *
 * Two important roles:
 *  1) Catch detection regressions — known SQLi/XSS/LFI/RCE payloads must
 *     still be blocked when we bump the parser or add new operators.
 *  2) Catch false-positive regressions — common benign traffic must NOT
 *     be blocked. Configuration bugs (missing TX defaults, unexpanded
 *     %{} references, scanner UA misparsing) historically show up here.
 *
 * Skips itself if the rules/ directory hasn't been populated by
 * bin/refresh-crs yet (so the suite still passes in fresh checkouts).
 */
final class RealCrsSmokeTest extends TestCase
{
    private static ?CrsEngine $crsEngine = null;

    public static function setUpBeforeClass(): void
    {
        $compiled = dirname(__DIR__, 2) . '/rules/compiled.php';
        if (!is_file($compiled)) {
            self::markTestSkipped('Real CRS rules not present — run bin/refresh-crs to populate rules/.');
        }

        self::$crsEngine = new CrsEngine(new CrsConfig(paranoia: 1));
    }

    /**
     * @return iterable<string, array{0: array<string, string>, 1: string, 2: ?string, 3: array<string, string>}>
     */
    public static function attackProvider(): iterable
    {
        // Tuple: [queryArgs, method, body, headers]
        //
        // Bare "' OR 1=1" is intentionally NOT in this list — CRS 4.x moved
        // simple-tautology detection to paranoia-2 (too false-positive-prone
        // at PL1). It's covered by the PL2 smoke test instead.
        yield 'sqli-union-select'      => [['id' => '1 UNION SELECT password FROM users'], 'GET', null, []];
        yield 'sqli-union-from'        => [['q' => "' UNION SELECT 1,2,3 FROM users--"], 'GET', null, []];
        yield 'sqli-sleep-blind'       => [['q' => "1' AND SLEEP(5)--"], 'GET', null, []];
        yield 'sqli-benchmark'         => [['q' => "1) AND BENCHMARK(1000000,MD5('a'))--"], 'GET', null, []];
        yield 'sqli-url-encoded-union' => [['q' => '%27%20UNION%20SELECT%201%2C2%2C3%20FROM%20users'], 'GET', null, []];

        yield 'xss-script-tag'         => [['c' => '<script>alert(1)</script>'], 'GET', null, []];
        yield 'xss-javascript-uri'     => [['u' => 'javascript:alert(1)'], 'GET', null, []];
        yield 'xss-event-handler'      => [['h' => '<img src=x onerror=alert(1)>'], 'GET', null, []];
        yield 'xss-html-entity-encoded' => [['h' => '&lt;script&gt;alert(1)&lt;/script&gt;'], 'GET', null, []];

        yield 'lfi-passwd'             => [['file' => '../../../../etc/passwd'], 'GET', null, []];
        yield 'rce-shell'              => [['cmd' => '; cat /etc/passwd'], 'GET', null, []];
        yield 'php-injection'          => [['p' => '<?php system($_GET[c]); ?>'], 'GET', null, []];

        yield 'scanner-ua-sqlmap'      => [[], 'GET', null, ['User-Agent' => 'sqlmap/1.5.2#stable (http://sqlmap.org)']];
        yield 'scanner-ua-nikto'       => [[], 'GET', null, ['User-Agent' => 'Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000001)']];
    }

    /**
     * @return iterable<string, array{0: array<string, string>, 1: string, 2: ?string, 3: array<string, string>}>
     */
    public static function benignProvider(): iterable
    {
        yield 'plain-search-query'         => [['q' => 'best restaurants near me'], 'GET', null, []];
        yield 'plain-hello'                => [['q' => 'hello world this is fine'], 'GET', null, []];
        yield 'normal-browser-chrome'      => [[], 'GET', null, ['User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36']];
        yield 'normal-browser-firefox'     => [[], 'GET', null, ['User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0']];
        yield 'normal-browser-safari'      => [[], 'GET', null, ['User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15']];
        yield 'multi-word-query'           => [['name' => "Sean O'Brien"], 'GET', null, []];
        yield 'iso-language-codes'         => [['locale' => 'en-US', 'tz' => 'America/New_York'], 'GET', null, []];
        yield 'json-api-request'           => [['action' => 'create'], 'POST', '{"name":"Acme Inc","plan":"pro"}', ['Content-Type' => 'application/json']];
        yield 'form-submission'            => [[], 'POST', null, ['Content-Type' => 'application/x-www-form-urlencoded']];
    }

    #[DataProvider('attackProvider')]
    public function testAttackPayloadIsBlocked(array $args, string $method, ?string $body, array $headers): void
    {
        $crsVerdict = self::$crsEngine->evaluate($this->req($args, $method, $body, $headers));
        $this->assertTrue(
            $crsVerdict->isBlocked(),
            sprintf(
                'Expected block. Got %s (score=%d, matched=%d rules)',
                $crsVerdict->action,
                $crsVerdict->totalScore,
                count($crsVerdict->matchedRules),
            )
        );
    }

    #[DataProvider('benignProvider')]
    public function testBenignTrafficIsNotBlocked(array $args, string $method, ?string $body, array $headers): void
    {
        $crsVerdict = self::$crsEngine->evaluate($this->req($args, $method, $body, $headers));
        $this->assertFalse(
            $crsVerdict->isBlocked(),
            sprintf(
                'Benign request was blocked by rule %s. Matched rules: %s',
                $crsVerdict->blockingRuleId ?? '(none)',
                json_encode(array_map(static fn (array $r): string => $r['id'] . ' ' . $r['msg'], $crsVerdict->matchedRules)),
            )
        );
    }

    public function testParanoiaTwoCatchesClassicTautology(): void
    {
        $compiled = dirname(__DIR__, 2) . '/rules/compiled.php';
        if (!is_file($compiled)) {
            self::markTestSkipped('Real CRS rules not present.');
        }

        $crsEngine = new CrsEngine(new CrsConfig(paranoia: 2));
        $crsVerdict = $crsEngine->evaluate($this->req(['login' => "' OR 1=1"], 'GET'));
        $this->assertTrue($crsVerdict->isBlocked(), 'Classic OR-tautology should block at paranoia level 2');
    }

    public function testResponseSqlErrorLeakIsBlocked(): void
    {
        $crsVerdict = self::$crsEngine->evaluateResponse(
            $this->req([], 'GET'),
            new ResponseData(
                status: 500,
                headers: ['Content-Type' => 'text/html'],
                body: 'Error: You have an error in your SQL syntax near line 1',
            ),
        );
        $this->assertTrue($crsVerdict->isBlocked(), 'MySQL syntax error leakage should block in response phase');
    }

    public function testBenignResponseIsAllowed(): void
    {
        $crsVerdict = self::$crsEngine->evaluateResponse(
            $this->req([], 'GET'),
            new ResponseData(status: 200, headers: ['Content-Type' => 'text/html'], body: '<html>Welcome</html>'),
        );
        $this->assertFalse($crsVerdict->isBlocked());
    }

    private function req(array $args, string $method, ?string $body = null, array $headers = []): RequestData
    {
        $qs = http_build_query($args);
        $headers += [
            'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Host'       => 'example.com',
            'Accept'     => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language' => 'en-US,en;q=0.5',
        ];

        return new RequestData(
            method: $method,
            uri: '/' . ($qs === '' ? '' : '?' . $qs),
            rawUri: '/' . ($qs === '' ? '' : '?' . $qs),
            queryString: $qs,
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.10',
            queryArgs: $method === 'GET' ? $args : [],
            postArgs: $method === 'GET' ? [] : $args,
            headers: $headers,
            body: $body ?? '',
        );
    }
}

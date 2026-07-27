<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\Request\RequestData;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Detection efficacy against the real bundled ruleset.
 *
 * This is the guard the project did not have: every defect fixed so far
 * (#1, #2, #13, #16) left the engine reporting a healthy rule count while
 * silently enforcing far less. A corpus test fails loudly instead.
 *
 * It also pins the false-positive profile of the one engine-owned rule,
 * 948100 — see supplemental/REQUEST-948-TAUTOLOGY.conf. A rule that ships
 * on by default at the default paranoia level has to stay quiet on ordinary
 * content, and "quiet" needs to be measured rather than assumed.
 */
final class PayloadCorpusTest extends TestCase
{
    private function engine(int $paranoia): CrsEngine
    {
        return new CrsEngine(new CrsConfig(paranoia: $paranoia, mode: CrsConfig::MODE_BLOCK));
    }

    /**
     * @param array<string, string> $args
     */
    private function request(array $args): RequestData
    {
        $qs = http_build_query($args);

        return new RequestData(
            method: 'GET',
            uri: '/search?' . $qs,
            rawUri: '/search?' . $qs,
            queryString: $qs,
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            queryArgs: $args,
            headers: [
                'Host'            => 'example.com',
                'User-Agent'      => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
                'Accept'          => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language' => 'en-US,en;q=0.5',
            ],
        );
    }

    /**
     * SQL tautologies, the family 948100 exists to catch. All must be blocked
     * at the default paranoia level.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function tautologyProvider(): iterable
    {
        yield 'quoted-classic'      => ["1' OR '1'='1"];
        yield 'quoted-trailing'     => ["1' or '1'='1' #"];
        yield 'quoted-named'        => ["admin' OR 'x'='x"];
        yield 'quoted-alpha'        => ["x' OR 'a'='a"];
        yield 'quoted-comment-tail' => ["' or 1=1--"];
        yield 'paren-wrapped'       => ["1') OR ('1'='1"];
        yield 'bare-numeric-or'     => ['1 OR 1=1'];
        yield 'bare-numeric-and'    => ['1 and 1=1'];
        yield 'bare-other-numeral'  => ['1 OR 2=2'];
        yield 'bare-large-numeral'  => ['9999 or 7=7'];
    }

    /**
     * Ordinary content, including deliberate near-misses built to trip the
     * tautology pattern. None may be blocked at the default paranoia level.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function benignProvider(): iterable
    {
        // Prose containing or/and next to a comparison — the shape that made
        // the first draft of 948100 unshippable at 10 false positives in 20.
        yield 'and-with-assignment'   => ['salary and bonus = 100'];
        yield 'or-with-assignment'    => ['choose red or blue = your call'];
        yield 'and-between-compares'  => ['if x > 5 and y < 3 then stop'];
        yield 'range-filter'          => ['price >= 10 and price <= 20'];
        yield 'field-filter'          => ['filter: status = active and role = editor'];
        yield 'boolean-prose'         => ['true or false = maybe'];
        yield 'title-with-year'       => ['Rock and Roll = 1955'];
        yield 'spaced-self-equality'  => ["don't stop or 3 = 3 either"];
        yield 'spaced-self-eq-two'    => ['proof that 1 = 1 and 2 = 2'];
        yield 'apostrophe-and-eq'     => ["it's 5 and 5 = 10"];
        yield 'algebra'               => ['solve for x and x = 12'];
        yield 'inequality-prose'      => ['10 > 5 and 3 < 8'];
        yield 'kv-pair'               => ['x=1 and y=2'];
        yield 'plain-conjunction'     => ['Tom and Jerry'];

        // Everyday CMS and search traffic.
        yield 'search-plain'          => ['best restaurants near me'];
        yield 'search-punctuation'    => ['what is a 401(k)?'];
        yield 'search-quoted'         => ['"exact phrase search"'];
        yield 'search-ampersand'      => ['Johnson & Johnson annual report'];
        yield 'name-apostrophe'       => ["Sean O'Brien"];
        yield 'name-accents'          => ['Zoë Müller-García'];
        yield 'address'               => ["12 St. Mary's Rd, Flat 3/2, Glasgow G41 3AA"];
        yield 'email-plus'            => ['sean+crs-test@kanopi.com'];
        yield 'quoted-speech'         => ['She said: "we\'ll ship it Tuesday" -- and they did.'];
        yield 'sql-discussion'        => ['We should add an index on the users table for the email column'];
        yield 'currency'              => ['1,234.56'];
        yield 'percent'               => ['100% cotton'];
        yield 'version-string'        => ['v4.26.0-rc.1+build.77'];
        yield 'uuid'                  => ['9f8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d'];
    }

    #[DataProvider('tautologyProvider')]
    public function testTautologyIsBlockedAtTheDefaultParanoiaLevel(string $payload): void
    {
        $crsVerdict = $this->engine(1)->evaluate($this->request(['q' => $payload]));

        $this->assertTrue(
            $crsVerdict->isBlocked(),
            sprintf('Expected a block, got %s (score %d).', $crsVerdict->action, $crsVerdict->totalScore),
        );
    }

    #[DataProvider('benignProvider')]
    public function testBenignContentIsNotBlockedAtTheDefaultParanoiaLevel(string $payload): void
    {
        $crsVerdict = $this->engine(1)->evaluate($this->request(['q' => $payload]));

        $this->assertFalse(
            $crsVerdict->isBlocked(),
            sprintf(
                'Benign input blocked by rule %s. Matched: %s',
                $crsVerdict->blockingRuleId ?? '(none)',
                json_encode(array_map(
                    static fn (array $r): string => $r['id'] . ' ' . $r['msg'],
                    $crsVerdict->matchedRules,
                )),
            ),
        );
    }

    /**
     * The supplemental rule has to be present and positioned before CRS's
     * blocking evaluation, or its score is never aggregated.
     */
    public function testSupplementalRuleIsLoadedBeforeBlockingEvaluation(): void
    {
        $rules = (new CrsEngine(new CrsConfig()))->ruleSet()->all();

        $supplementalIndex = null;
        $firstBlockingIndex = null;
        foreach ($rules as $i => $rule) {
            if ($rule->id === 948100) {
                $supplementalIndex = $i;
            }

            if ($firstBlockingIndex === null && $rule->id >= 949000 && $rule->id < 950000) {
                $firstBlockingIndex = $i;
            }
        }

        $this->assertNotNull($supplementalIndex, 'Rule 948100 is missing — did a CRS refresh drop supplemental/?');
        $this->assertNotNull($firstBlockingIndex);
        $this->assertLessThan(
            $firstBlockingIndex,
            $supplementalIndex,
            'Rule 948100 must score before the 949 aggregation, or it never reaches the anomaly threshold.',
        );
    }

    /**
     * Guards the documented gap rather than the fix: these need tokenisation,
     * and the README says so. If one starts passing, the docs are now wrong.
     */
    public function testKnownPl1GapsAreStillDocumentedAccurately(): void
    {
        $stillMissed = [];
        foreach (['comment-terminator' => "admin'--", 'backtick-rce' => '`id`'] as $label => $payload) {
            if (!$this->engine(1)->evaluate($this->request(['q' => $payload]))->isBlocked()) {
                $stillMissed[] = $label;
            }
        }

        $this->assertSame(
            ['comment-terminator', 'backtick-rce'],
            $stillMissed,
            'A documented PL1 gap now behaves differently — update the README and supplemental/ notes.',
        );
    }
}

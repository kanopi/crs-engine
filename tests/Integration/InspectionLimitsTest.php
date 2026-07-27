<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\CrsVerdict;
use Kanopi\Crs\Request\RequestData;
use PHPUnit\Framework\TestCase;

/**
 * Integration: the inspection caps against the real bundled ruleset.
 *
 * The point of the caps is that an oversized request cannot buy unbounded CPU —
 * 5,000 arguments in a 130 KB body cost 2.2s before, versus 26ms for an
 * ordinary request. The point of keeping counting uncapped is that such a
 * request is still *flagged* rather than quietly half-inspected.
 *
 * No wall-clock assertions here: they are the first thing to go flaky on shared
 * CI. What is asserted is that the caps engage, that they are visible on the
 * verdict, and that the CRS rules which flag an over-large request still fire.
 */
final class InspectionLimitsTest extends TestCase
{
    private CrsEngine $crsEngine;

    protected function setUp(): void
    {
        $this->crsEngine = new CrsEngine(new CrsConfig(paranoia: 1));
    }

    /**
     * @param array<string, string> $post
     */
    private function verdict(array $post, ?CrsEngine $crsEngine = null): CrsVerdict
    {
        $body = http_build_query($post);

        return ($crsEngine ?? $this->crsEngine)->evaluate(new RequestData(
            method: 'POST',
            uri: '/index.php',
            rawUri: '/index.php',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '203.0.113.9',
            postArgs: $post,
            headers: [
                'host'           => 'example.test',
                'content-type'   => 'application/x-www-form-urlencoded',
                'content-length' => (string) strlen($body),
            ],
            body: $body,
        ));
    }

    /**
     * @return array<string, string>
     */
    private function manyArgs(int $count): array
    {
        $post = [];
        for ($i = 0; $i < $count; $i++) {
            $post['p' . $i] = 'value' . $i;
        }

        return $post;
    }

    public function testAnOrdinaryRequestIsNotTruncated(): void
    {
        $crsVerdict = $this->verdict(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);

        $this->assertFalse($crsVerdict->wasTruncated());
        $this->assertSame([], $crsVerdict->truncations);
        $this->assertFalse($crsVerdict->isBlocked());
    }

    public function testTooManyArgumentsIsCappedAndStillFlagged(): void
    {
        $crsVerdict = $this->verdict($this->manyArgs(5000));

        $this->assertTrue($crsVerdict->wasTruncated(), 'The cap should have engaged.');
        $this->assertContains(
            920380,
            array_column($crsVerdict->matchedRules, 'id'),
            'Counting stays uncapped, so the too-many-arguments rule must still fire.'
        );
        $this->assertTrue($crsVerdict->isBlocked(), 'An over-large request should not sail through.');
    }

    public function testTruncationRecordsWhatWasSkipped(): void
    {
        $crsVerdict = $this->verdict($this->manyArgs(1000));

        $args = null;
        foreach ($crsVerdict->truncations as $truncation) {
            if ($truncation['what'] === 'args') {
                $args = $truncation;
            }
        }

        $this->assertNotNull($args, 'An args truncation should be reported.');
        $this->assertSame(CrsConfig::DEFAULT_MAX_ARGS, $args['inspected']);
        $this->assertSame(1000, $args['total']);
    }

    public function testAPayloadWithinTheCapsIsStillDetected(): void
    {
        $crsVerdict = $this->verdict(['q' => "' OR 1=1 -- "]);

        $this->assertFalse($crsVerdict->wasTruncated());
        $this->assertTrue($crsVerdict->isBlocked());
    }

    /**
     * The payload sits in the first argument, so the caps must not stop it being
     * seen just because later arguments push the request over a limit.
     */
    public function testAPayloadInAnEarlyArgumentSurvivesTruncation(): void
    {
        $crsVerdict = $this->verdict(['q' => "' OR 1=1 -- ", ...$this->manyArgs(2000)]);

        $this->assertTrue($crsVerdict->wasTruncated());
        $this->assertContains(
            948100,
            array_column($crsVerdict->matchedRules, 'id'),
            'A payload inside the inspected window must still be found.'
        );
    }

    public function testAPayloadAtTheFrontOfAnOversizedArgumentIsStillFound(): void
    {
        $crsVerdict = $this->verdict(['q' => "' OR 1=1 -- " . str_repeat('.', 400_000)]);

        $this->assertTrue($crsVerdict->wasTruncated());
        $this->assertTrue(
            $crsVerdict->isBlocked(),
            'The value crossing the byte budget keeps its prefix, so a leading payload is caught.'
        );
    }

    public function testAnOversizedArgumentIsBlockedEvenWhenItsPayloadIsCutOff(): void
    {
        // Payload past the byte budget, so the SQLi rules cannot see it. The
        // request should still not be reported clean.
        $crsVerdict = $this->verdict(['q' => str_repeat('.', 400_000) . "' OR 1=1 -- "]);

        $this->assertTrue($crsVerdict->wasTruncated());
        $this->assertTrue(
            $crsVerdict->isBlocked(),
            'An argument too large to inspect is itself anomalous and CRS flags it.'
        );
    }

    public function testUnlimitedConfigInspectsEverything(): void
    {
        $crsEngine = new CrsEngine(new CrsConfig(
            paranoia: 1,
            maxArgs: CrsConfig::UNLIMITED,
            maxRequestBodyBytes: CrsConfig::UNLIMITED,
            maxArgBytes: CrsConfig::UNLIMITED,
            maxResponseBodyBytes: CrsConfig::UNLIMITED,
        ));

        $crsVerdict = $this->verdict($this->manyArgs(1000), $crsEngine);

        $this->assertFalse($crsVerdict->wasTruncated(), 'UNLIMITED must disable the caps.');
    }

    public function testTruncationsAppearInToArray(): void
    {
        $asArray = $this->verdict($this->manyArgs(1000))->toArray();

        $this->assertArrayHasKey('truncations', $asArray);
        $this->assertNotSame([], $asArray['truncations']);
    }
}

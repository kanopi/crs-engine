<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Parser;

use Kanopi\Crs\Parser\SecLangParser;
use PHPUnit\Framework\TestCase;

/**
 * The parser must emit SecMarker placeholders in position — a skipAfter
 * earlier in the file has nowhere to land otherwise.
 */
final class SecMarkerTest extends TestCase
{
    public function testMarkerIsEmittedInPosition(): void
    {
        $conf = <<<'CONF'
        SecRule ARGS "@rx attack" "id:1,phase:2,pass,skipAfter:END-FOO"
        SecRule ARGS "@rx other" "id:2,phase:2,pass"
        SecMarker "END-FOO"
        SecRule ARGS "@rx third" "id:3,phase:2,pass"
        CONF;

        $rules = (new SecLangParser())->parseString($conf, 'REQUEST-900-TEST.conf');

        $this->assertCount(4, $rules);
        $this->assertNull($rules[0]->marker);
        $this->assertNull($rules[1]->marker);
        $this->assertSame('END-FOO', $rules[2]->marker);
        $this->assertNull($rules[3]->marker);
        $this->assertSame(3, $rules[3]->id);
    }

    public function testUnquotedMarkerNameIsParsed(): void
    {
        $rules = (new SecLangParser())->parseString('SecMarker END-BAR', 'REQUEST-900-TEST.conf');

        $this->assertCount(1, $rules);
        $this->assertSame('END-BAR', $rules[0]->marker);
    }

    public function testMarkerSurvivesToArrayRoundTrip(): void
    {
        $rules = (new SecLangParser())->parseString('SecMarker "END-BAZ"', 'REQUEST-900-TEST.conf');
        $array = $rules[0]->toArray();

        $this->assertSame('END-BAZ', $array['marker']);
    }

    /**
     * A marker must not be absorbed into an unterminated chain — it has to
     * keep its own position so a skipAfter can land on it.
     *
     * The chain child here carries an `id` only because the parser currently
     * drops id-less continuations (see #16); this test is about marker
     * ordering, not chain semantics, and should keep passing once #16 lands.
     */
    public function testMarkerIsNotAbsorbedIntoAnOpenChain(): void
    {
        $conf = <<<'CONF'
        SecRule ARGS "@rx a" "id:10,phase:2,pass,chain"
            SecRule ARGS "@rx b" "id:11,phase:2,pass"
        SecMarker "END-QUX"
        CONF;

        $rules = (new SecLangParser())->parseString($conf, 'REQUEST-900-TEST.conf');

        $this->assertCount(2, $rules);
        $this->assertSame(10, $rules[0]->id);
        $this->assertNull($rules[0]->marker);
        $this->assertSame('END-QUX', $rules[1]->marker);
    }

    public function testEmptyMarkerNameIsSkipped(): void
    {
        $rules = (new SecLangParser())->parseString('SecMarker', 'REQUEST-900-TEST.conf');

        $this->assertSame([], $rules);
    }
}

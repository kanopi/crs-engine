<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Runtime;

use Kanopi\Crs\Parser\SecLangParser;
use Kanopi\Crs\Refresh\RuleWriter;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

/**
 * The static memo on RuleSet::loadFromDirectory makes subsequent loads
 * from the same path effectively free — the same way FPM workers handle
 * the production hot path across many requests.
 */
final class RuleSetCacheTest extends TestCase
{
    private string $tmp;

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/crs-engine-cache-test-' . bin2hex(random_bytes(4));
        mkdir($this->tmp, 0755, true);

        $secLangParser = new SecLangParser();
        $parsed = $secLangParser->parseFile(dirname(__DIR__, 2) . '/Integration/fixtures/REQUEST-942-APPLICATION-ATTACK-SQLI.conf');
        (new RuleWriter($this->tmp))->write(['REQUEST-942.conf' => $parsed], 'test', []);
    }

    protected function tearDown(): void
    {
        RuleSet::clearProcessCache();
        foreach (scandir($this->tmp) ?: [] as $f) {
            if ($f !== '.' && $f !== '..') {
                unlink($this->tmp . '/' . $f);
            }
        }

        rmdir($this->tmp);
    }

    public function testSecondLoadReturnsSameInstance(): void
    {
        $ruleSet = RuleSet::loadFromDirectory($this->tmp);
        $b = RuleSet::loadFromDirectory($this->tmp);
        $this->assertSame($ruleSet, $b, 'Second load should hit process cache and return identical instance');
    }

    public function testUseCacheFalseBypassesMemo(): void
    {
        $ruleSet = RuleSet::loadFromDirectory($this->tmp);
        $b = RuleSet::loadFromDirectory($this->tmp, useCache: false);
        $this->assertNotSame($ruleSet, $b, 'useCache: false should force a fresh load');
        $this->assertSame($ruleSet->count(), $b->count(), 'Content equivalent though');
    }

    public function testClearProcessCacheForcesReload(): void
    {
        $ruleSet = RuleSet::loadFromDirectory($this->tmp);
        RuleSet::clearProcessCache();
        $b = RuleSet::loadFromDirectory($this->tmp);
        $this->assertNotSame($ruleSet, $b);
    }

    public function testDifferentDirectoriesAreCachedSeparately(): void
    {
        $other = sys_get_temp_dir() . '/crs-engine-cache-test-2-' . bin2hex(random_bytes(4));
        mkdir($other, 0755, true);
        try {
            $secLangParser = new SecLangParser();
            $parsed = $secLangParser->parseFile(dirname(__DIR__, 2) . '/Integration/fixtures/REQUEST-941-APPLICATION-ATTACK-XSS.conf');
            (new RuleWriter($other))->write(['REQUEST-941.conf' => $parsed], 'test', []);

            $sqli = RuleSet::loadFromDirectory($this->tmp);
            $xss  = RuleSet::loadFromDirectory($other);
            $this->assertNotSame($sqli, $xss);
            $this->assertSame($sqli, RuleSet::loadFromDirectory($this->tmp));
        } finally {
            foreach (scandir($other) ?: [] as $f) {
                if ($f !== '.' && $f !== '..') {
                    unlink($other . '/' . $f);
                }
            }

            rmdir($other);
        }
    }
}

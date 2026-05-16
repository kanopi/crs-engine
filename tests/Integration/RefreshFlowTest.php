<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\Parser\SecLangParser;
use Kanopi\Crs\Refresh\RuleWriter;
use Kanopi\Crs\Refresh\VersionPin;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

/**
 * Exercises the parse → write → load round-trip without hitting the network.
 */
final class RefreshFlowTest extends TestCase
{
    private string $tmp;

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/crs-engine-test-' . bin2hex(random_bytes(4));
        mkdir($this->tmp, 0755, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tmp)) {
            $this->rrmdir($this->tmp);
        }
    }

    public function testWriteThenLoadRoundtrip(): void
    {
        $secLangParser = new SecLangParser();
        $sqli = $secLangParser->parseFile(__DIR__ . '/fixtures/REQUEST-942-APPLICATION-ATTACK-SQLI.conf');
        $xss  = $secLangParser->parseFile(__DIR__ . '/fixtures/REQUEST-941-APPLICATION-ATTACK-XSS.conf');

        $ruleWriter = new RuleWriter($this->tmp);
        $stats = $ruleWriter->write(
            [
                'REQUEST-942-APPLICATION-ATTACK-SQLI.conf' => $sqli,
                'REQUEST-941-APPLICATION-ATTACK-XSS.conf'  => $xss,
            ],
            'v-test',
            $secLangParser->warnings
        );
        $this->assertGreaterThan(0, $stats['rule_count']);
        $this->assertFileExists($this->tmp . '/manifest.json');
        $this->assertFileExists($this->tmp . '/compiled.php');
        $this->assertFileExists($this->tmp . '/REQUEST-942-APPLICATION-ATTACK-SQLI.json');

        $ruleSet = RuleSet::loadFromDirectory($this->tmp);
        $this->assertSame($stats['rule_count'], $ruleSet->count());
        $this->assertSame('v-test', $ruleSet->crsVersion());
    }

    public function testVersionPinReadWrite(): void
    {
        $pinPath = $this->tmp . '/.crs-version';
        file_put_contents($pinPath, "tag=v4.0.0\nsha=\nsource=https://github.com/coreruleset/coreruleset\n");
        $versionPin = new VersionPin($pinPath);
        $data = $versionPin->read();
        $this->assertSame('v4.0.0', $data['tag']);

        $versionPin->write(['tag' => 'v4.1.0']);
        $data2 = $versionPin->read();
        $this->assertSame('v4.1.0', $data2['tag']);
        $this->assertSame('https://github.com/coreruleset/coreruleset', $data2['source']);
    }

    private function rrmdir(string $dir): void
    {
        foreach (scandir($dir) ?: [] as $item) {
            if ($item === '.') {
                continue;
            }

            if ($item === '..') {
                continue;
            }

            $path = $dir . '/' . $item;
            is_dir($path) ? $this->rrmdir($path) : unlink($path);
        }

        rmdir($dir);
    }
}

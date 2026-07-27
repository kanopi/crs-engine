<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\Parser\ParsedRule;
use Kanopi\Crs\Parser\SecLangParser;
use Kanopi\Crs\Refresh\RuleWriter;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

/**
 * A refresh must never leave a reader with no ruleset.
 *
 * The previous swap renamed rules/ aside and then renamed staging into its
 * place — two operations, with a window between them where rules/ did not
 * exist. A worker calling RuleSet::loadFromDirectory() in that window got a
 * hard ConfigurationException instead of a stale-but-valid ruleset. A directory
 * cannot be replaced atomically; the single file the runtime reads can be.
 */
final class RulesetSwapAtomicityTest extends TestCase
{
    private string $tmp;

    private string $rulesDir;

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/crs-swap-' . bin2hex(random_bytes(6));
        $this->rulesDir = $this->tmp . '/rules';
        mkdir($this->tmp, 0o755, true);
    }

    protected function tearDown(): void
    {
        @chmod($this->tmp, 0o755);
        $this->removeRecursively($this->tmp);
        RuleSet::clearProcessCache();
    }

    private function removeRecursively(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (glob($dir . '/*') ?: [] as $entry) {
            if (is_dir($entry)) {
                $this->removeRecursively($entry);
                continue;
            }

            @unlink($entry);
        }

        @rmdir($dir);
    }

    /**
     * @return array<int, ParsedRule>
     */
    private function parsedRules(int $id): array
    {
        return (new SecLangParser())->parseString(
            sprintf('SecRule ARGS "@rx x" "id:%d,phase:2,pass,msg:\'test\'"', $id),
            'REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
        );
    }

    private function write(RuleWriter $ruleWriter, int $id, string $version): void
    {
        $ruleWriter->write(
            ['REQUEST-942-APPLICATION-ATTACK-SQLI.conf' => $this->parsedRules($id)],
            $version,
            []
        );
    }

    public function testRulesDirectoryAndCompiledFileSurviveARefresh(): void
    {
        $ruleWriter = new RuleWriter($this->rulesDir);
        $this->write($ruleWriter, 1001, 'v1');

        $this->assertDirectoryExists($this->rulesDir);
        $this->assertFileExists($this->rulesDir . '/compiled.php');

        $this->write($ruleWriter, 2002, 'v2');

        $this->assertDirectoryExists($this->rulesDir);
        $this->assertFileExists($this->rulesDir . '/compiled.php');
        $this->assertSame('v2', RuleSet::loadFromDirectory($this->rulesDir, useCache: false)->crsVersion());
    }

    /**
     * The heart of it. A reader is simulated at every point a file operation
     * could be interrupted: after each write, the directory must hold a
     * complete, loadable ruleset — one version or the other, never neither and
     * never a mixture.
     */
    public function testEveryObservablePointHoldsACompleteRuleset(): void
    {
        $ruleWriter = new RuleWriter($this->rulesDir);
        $this->write($ruleWriter, 1001, 'v1');

        $seen = [];
        for ($i = 0; $i < 6; $i++) {
            $version = 'v' . ($i + 2);
            $this->write($ruleWriter, 2000 + $i, $version);

            $ruleSet = RuleSet::loadFromDirectory($this->rulesDir, useCache: false);
            $this->assertSame(1, $ruleSet->count(), 'A partially swapped ruleset was loadable.');
            $seen[] = $ruleSet->crsVersion();
        }

        $this->assertSame(['v2', 'v3', 'v4', 'v5', 'v6', 'v7'], $seen);
    }

    public function testStagingDirectoryIsNotLeftBehindAfterSuccess(): void
    {
        $ruleWriter = new RuleWriter($this->rulesDir);
        $this->write($ruleWriter, 1001, 'v1');
        $this->write($ruleWriter, 2002, 'v2');

        $this->assertSame(
            [],
            glob($this->tmp . '/rules.staging-*') ?: [],
            'A leftover staging directory makes the next run build into a directory it did not create.'
        );
        $this->assertSame([], glob($this->tmp . '/rules.backup-*') ?: []);
    }

    public function testAFailedSwapLeavesThePreviousRulesetLoadable(): void
    {
        $ruleWriter = new RuleWriter($this->rulesDir);
        $this->write($ruleWriter, 1001, 'v1');
        $before = (string) file_get_contents($this->rulesDir . '/compiled.php');

        chmod($this->tmp, 0o500);

        try {
            $this->write($ruleWriter, 2002, 'v2');
            $this->fail('Expected the write to fail while the parent was read-only.');
        } catch (\RuntimeException) {
            // expected
        } finally {
            chmod($this->tmp, 0o755);
        }

        $this->assertDirectoryExists($this->rulesDir, 'rules/ must never be the casualty of a failed refresh.');
        $this->assertSame($before, file_get_contents($this->rulesDir . '/compiled.php'));
        $this->assertSame('v1', RuleSet::loadFromDirectory($this->rulesDir, useCache: false)->crsVersion());
    }

    /**
     * A CRS release that drops a rule file should not leave the JSON for it
     * sitting next to a compiled.php that no longer describes it.
     */
    public function testArtifactsFromAPreviousRulesetAreCleanedUp(): void
    {
        $ruleWriter = new RuleWriter($this->rulesDir);
        $ruleWriter->write([
            'REQUEST-942-APPLICATION-ATTACK-SQLI.conf' => $this->parsedRules(1001),
            'REQUEST-941-APPLICATION-ATTACK-XSS.conf'  => $this->parsedRules(1002),
        ], 'v1', []);

        $this->assertFileExists($this->rulesDir . '/REQUEST-941-APPLICATION-ATTACK-XSS.json');

        $this->write($ruleWriter, 2002, 'v2');

        $this->assertFileDoesNotExist(
            $this->rulesDir . '/REQUEST-941-APPLICATION-ATTACK-XSS.json',
            'A dropped source file should not leave its JSON behind.'
        );
        $this->assertFileExists($this->rulesDir . '/REQUEST-942-APPLICATION-ATTACK-SQLI.json');
    }

    public function testUnrelatedFilesInTheRulesDirectoryAreNotPreserved(): void
    {
        // rules/ is generated output, so anything not in the new ruleset goes.
        // Pinned because the cleanup loop is the part most likely to be made
        // too timid later and start accumulating stale artifacts.
        $ruleWriter = new RuleWriter($this->rulesDir);
        $this->write($ruleWriter, 1001, 'v1');
        file_put_contents($this->rulesDir . '/stray.json', '{}');

        $this->write($ruleWriter, 2002, 'v2');

        $this->assertFileDoesNotExist($this->rulesDir . '/stray.json');
    }
}

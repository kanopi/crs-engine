<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\Exception\CrsEngineException;
use Kanopi\Crs\Parser\SecLangParser;
use Kanopi\Crs\Refresh\CrsSource;
use Kanopi\Crs\Refresh\RefreshRunner;
use Kanopi\Crs\Refresh\VersionPin;
use Kanopi\Crs\Refresh\RulesetDigest;
use Kanopi\Crs\Refresh\RuleWriter;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

/**
 * The refresh job runs unattended in CI. Two things must hold when it goes
 * wrong: a ruleset that is not the pinned one must be rejected, and a failed
 * write must leave the previous ruleset exactly as it was.
 *
 * Before this, RuleWriter deleted every *.json and compiled.php as its first
 * action and then wrote replacements one at a time with unchecked
 * file_put_contents(). A failure part-way through left rules/ with no
 * compiled.php and an arbitrary subset of the JSON — which
 * RuleSet::loadFromDirectory() would then load as though it were the whole
 * ruleset, silently enforcing a fraction of it.
 */
final class RefreshFailureModesTest extends TestCase
{
    private string $tmp;

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/crs-refresh-test-' . bin2hex(random_bytes(6));
        mkdir($this->tmp, 0755, true);
    }

    protected function tearDown(): void
    {
        @chmod($this->tmp, 0755);
        $this->removeRecursively($this->tmp);
    }

    private function removeRecursively(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (glob($dir . '/*') ?: [] as $entry) {
            is_dir($entry) ? $this->removeRecursively($entry) : @unlink($entry);
        }

        @rmdir($dir);
    }

    /**
     * @return array<int, \Kanopi\Crs\Parser\ParsedRule>
     */
    private function parsedRules(int $id): array
    {
        return (new SecLangParser())->parseString(
            sprintf('SecRule ARGS "@rx x" "id:%d,phase:2,pass,msg:\'test\'"', $id),
            'REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
        );
    }

    // ---------------------------------------------------------------- #11

    public function testASuccessfulWriteReplacesTheRuleset(): void
    {
        $rulesDir = $this->tmp . '/rules';
        $ruleWriter = new RuleWriter($rulesDir);

        $ruleWriter->write(['REQUEST-942-APPLICATION-ATTACK-SQLI.conf' => $this->parsedRules(1001)], 'v1', []);

        $this->assertFileExists($rulesDir . '/compiled.php');
        $this->assertSame(1, RuleSet::loadFromDirectory($rulesDir, useCache: false)->count());
    }

    public function testAFailedWriteLeavesThePreviousRulesetIntact(): void
    {
        $rulesDir = $this->tmp . '/rules';
        $ruleWriter = new RuleWriter($rulesDir);
        $ruleWriter->write(['REQUEST-942-APPLICATION-ATTACK-SQLI.conf' => $this->parsedRules(1001)], 'v1', []);

        $before = file_get_contents($rulesDir . '/compiled.php');

        // Staging is created alongside rules/, so a read-only parent makes the
        // write fail at exactly the point the old code would already have
        // deleted the live ruleset.
        chmod($this->tmp, 0500);

        try {
            $ruleWriter->write(['REQUEST-942-APPLICATION-ATTACK-SQLI.conf' => $this->parsedRules(2002)], 'v2', []);
            $this->fail('Expected the write to fail while the directory was read-only.');
        } catch (\RuntimeException) {
            // expected
        } finally {
            chmod($this->tmp, 0755);
        }

        $this->assertFileExists($rulesDir . '/compiled.php', 'The previous ruleset was destroyed by a failed write.');
        $this->assertSame($before, file_get_contents($rulesDir . '/compiled.php'));
        $this->assertSame(1, RuleSet::loadFromDirectory($rulesDir, useCache: false)->count());
    }

    public function testNoStagingDirectoryIsLeftBehindAfterAFailure(): void
    {
        $rulesDir = $this->tmp . '/rules';
        $ruleWriter = new RuleWriter($rulesDir);
        $ruleWriter->write(['REQUEST-942-APPLICATION-ATTACK-SQLI.conf' => $this->parsedRules(1001)], 'v1', []);

        chmod($this->tmp, 0500);

        try {
            $ruleWriter->write(['REQUEST-942-APPLICATION-ATTACK-SQLI.conf' => $this->parsedRules(2002)], 'v2', []);
        } catch (\RuntimeException) {
            // expected
        } finally {
            chmod($this->tmp, 0755);
        }

        $this->assertSame(
            [],
            glob($this->tmp . '/rules.staging-*') ?: [],
            'A staging directory survived a failed refresh.',
        );
        $this->assertSame([], glob($this->tmp . '/rules.backup-*') ?: []);
    }

    public function testWriterOnlyTouchesItsOwnDirectory(): void
    {
        $bystander = $this->tmp . '/not-the-ruleset.json';
        file_put_contents($bystander, '{"keep":true}');

        (new RuleWriter($this->tmp . '/rules'))
            ->write(['REQUEST-942-APPLICATION-ATTACK-SQLI.conf' => $this->parsedRules(1001)], 'v1', []);

        $this->assertSame('{"keep":true}', file_get_contents($bystander));
    }

    // ----------------------------------------------------------------- #5

    public function testDigestIsStableForIdenticalContent(): void
    {
        $a = $this->tmp . '/a';
        $b = $this->tmp . '/b';
        foreach ([$a, $b] as $dir) {
            mkdir($dir, 0755, true);
            file_put_contents($dir . '/REQUEST-942.conf', 'SecRule ARGS "@rx x" "id:1"');
            file_put_contents($dir . '/lists.data', "one\ntwo\n");
        }

        $this->assertSame(RulesetDigest::forDirectory($a), RulesetDigest::forDirectory($b));
    }

    public function testDigestChangesWhenARuleFileChanges(): void
    {
        $dir = $this->tmp . '/rules-src';
        mkdir($dir, 0755, true);
        file_put_contents($dir . '/REQUEST-942.conf', 'SecRule ARGS "@rx x" "id:1"');
        $before = RulesetDigest::forDirectory($dir);

        file_put_contents($dir . '/REQUEST-942.conf', 'SecRule ARGS "@rx evil" "id:1"');

        $this->assertNotSame($before, RulesetDigest::forDirectory($dir));
    }

    /**
     * An added file is a content change too — a rule injected into a release
     * must not slip past because the existing files are untouched.
     */
    public function testDigestChangesWhenAFileIsAdded(): void
    {
        $dir = $this->tmp . '/rules-src';
        mkdir($dir, 0755, true);
        file_put_contents($dir . '/REQUEST-942.conf', 'SecRule ARGS "@rx x" "id:1"');
        $before = RulesetDigest::forDirectory($dir);

        file_put_contents($dir . '/REQUEST-999-INJECTED.conf', 'SecRule ARGS "@rx y" "id:2"');

        $this->assertNotSame($before, RulesetDigest::forDirectory($dir));
    }

    public function testDigestIsIndependentOfFileOrderOnDisk(): void
    {
        $dir = $this->tmp . '/rules-src';
        mkdir($dir, 0755, true);
        file_put_contents($dir . '/b.conf', 'second');
        file_put_contents($dir . '/a.conf', 'first');
        $first = RulesetDigest::forDirectory($dir);

        // Rewrite in the opposite order; content is identical.
        unlink($dir . '/a.conf');
        unlink($dir . '/b.conf');
        file_put_contents($dir . '/a.conf', 'first');
        file_put_contents($dir . '/b.conf', 'second');

        $this->assertSame($first, RulesetDigest::forDirectory($dir));
    }

    public function testDigestRejectsAnEmptyDirectory(): void
    {
        $dir = $this->tmp . '/empty';
        mkdir($dir, 0755, true);

        $this->expectException(CrsEngineException::class);
        RulesetDigest::forDirectory($dir);
    }

    public function testShippedPinMatchesTheCompiledRuleset(): void
    {
        $pin = parse_ini_file(dirname(__DIR__, 2) . '/.crs-version');

        $this->assertIsArray($pin);
        $this->assertArrayHasKey('sha', $pin);
        $this->assertMatchesRegularExpression(
            '/^sha256:[0-9a-f]{64}$/',
            (string) $pin['sha'],
            'The shipped ruleset has no content pin, so a substituted CRS release would be accepted silently.',
        );
    }

    // -------------------------------------------- #5 through RefreshRunner

    /**
     * A CRS release already on disk. Lets the whole refresh flow run — digest
     * check included — without touching the network.
     */
    private function localSource(string $rulesPath): CrsSource
    {
        return new class ($rulesPath) implements CrsSource {
            public function __construct(private readonly string $rulesPath)
            {
            }

            public function fetchTag(string $tag, string $workDir): string
            {
                return $this->rulesPath;
            }

            public function latestTag(): string
            {
                return 'v9.9.9';
            }
        };
    }

    private function fakeRelease(string $body = 'SecRule ARGS "@rx x" "id:1,phase:2,pass,msg:\'t\'"'): string
    {
        $dir = $this->tmp . '/release/rules';
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        file_put_contents($dir . '/REQUEST-942-APPLICATION-ATTACK-SQLI.conf', $body);

        return $dir;
    }

    private function pinFile(string $tag, string $sha): VersionPin
    {
        $path = $this->tmp . '/.crs-version';
        file_put_contents($path, "tag={$tag}\nsha={$sha}\nsource=https://example.invalid/crs\n");

        return new VersionPin($path);
    }

    private function runner(VersionPin $versionPin, string $releaseRules, string $rulesDir): RefreshRunner
    {
        return new RefreshRunner(
            $versionPin,
            $this->localSource($releaseRules),
            new RuleWriter($rulesDir),
            $this->tmp . '/work',
        );
    }

    public function testRefreshRecordsTheDigestWhenThePinIsEmpty(): void
    {
        $rulesDir = $this->tmp . '/rules';
        $versionPin = $this->pinFile('v1.0.0', '');

        $result = $this->runner($versionPin, $this->fakeRelease(), $rulesDir)->run();

        $this->assertSame('recorded', $result['digest_state']);
        $this->assertMatchesRegularExpression('/^sha256:[0-9a-f]{64}$/', $result['digest']);
        $this->assertSame($result['digest'], $versionPin->read()['sha'], 'The digest must be written back so the next run can verify it.');
    }

    public function testRefreshVerifiesAMatchingDigest(): void
    {
        $rulesDir = $this->tmp . '/rules';
        $release = $this->fakeRelease();
        $versionPin = $this->pinFile('v1.0.0', RulesetDigest::forDirectory($release));

        $result = $this->runner($versionPin, $release, $rulesDir)->run();

        $this->assertSame('verified', $result['digest_state']);
    }

    /**
     * The core of #5: content that does not match the pin must be rejected,
     * and rules/ must be exactly as it was.
     */
    public function testRefreshRejectsASubstitutedRulesetAndLeavesRulesUntouched(): void
    {
        $rulesDir = $this->tmp . '/rules';
        $release = $this->fakeRelease();
        $versionPin = $this->pinFile('v1.0.0', RulesetDigest::forDirectory($release));

        // Establish a good ruleset first.
        $this->runner($versionPin, $release, $rulesDir)->run();
        $before = file_get_contents($rulesDir . '/compiled.php');

        // Someone re-tags the release with a different rule.
        $this->fakeRelease('SecRule ARGS "@rx evil" "id:1,phase:2,pass,msg:\'t\'"');

        try {
            $this->runner($versionPin, $release, $rulesDir)->run();
            $this->fail('A substituted ruleset was accepted.');
        } catch (CrsEngineException $crsEngineException) {
            $this->assertStringContainsString('digest mismatch', $crsEngineException->getMessage());
        }

        $this->assertSame($before, file_get_contents($rulesDir . '/compiled.php'), 'rules/ was modified despite the digest mismatch.');
    }

    public function testBumpRePinsDeliberately(): void
    {
        $rulesDir = $this->tmp . '/rules';
        $release = $this->fakeRelease();
        $versionPin = $this->pinFile('v1.0.0', 'sha256:' . str_repeat('0', 64));

        $result = $this->runner($versionPin, $release, $rulesDir)->run(bump: true);

        $this->assertSame('recorded', $result['digest_state']);
        $this->assertSame('v9.9.9', $result['tag']);
        $this->assertSame($result['digest'], $versionPin->read()['sha']);
    }
}

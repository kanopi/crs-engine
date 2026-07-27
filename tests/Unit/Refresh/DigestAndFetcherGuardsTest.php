<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Refresh;

use Kanopi\Crs\Exception\CrsEngineException;
use Kanopi\Crs\Refresh\CrsFetcher;
use Kanopi\Crs\Refresh\RulesetDigest;
use PHPUnit\Framework\TestCase;

/**
 * Guards on the one path that ingests content this project did not write.
 *
 * The digest detects substitution between two fetches; it is not a signature
 * and cannot establish a publisher. That makes the transport the only thing
 * authenticating the ruleset, and makes a digest that silently describes less
 * than the whole tree worse than an honest failure.
 */
final class DigestAndFetcherGuardsTest extends TestCase
{
    private string $workDir;

    protected function setUp(): void
    {
        $this->workDir = sys_get_temp_dir() . '/crs-digest-guards-' . bin2hex(random_bytes(6));
        mkdir($this->workDir . '/rules', 0o755, true);
        file_put_contents($this->workDir . '/rules/REQUEST-942.conf', "SecRule ARGS \"@rx x\" \"id:1\"\n");
        file_put_contents($this->workDir . '/rules/lfi-os-files.data', "etc/hosts\n");
    }

    protected function tearDown(): void
    {
        $nested = $this->workDir . '/rules/nested';
        if (is_file($nested . '/hidden.conf')) {
            unlink($nested . '/hidden.conf');
        }

        if (is_dir($nested)) {
            rmdir($nested);
        }

        foreach (glob($this->workDir . '/rules/*') ?: [] as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }

        foreach ([$this->workDir . '/rules', $this->workDir] as $dir) {
            if (is_dir($dir)) {
                rmdir($dir);
            }
        }
    }

    public function testDigestIsStableForAFlatTree(): void
    {
        $first = RulesetDigest::forDirectory($this->workDir . '/rules');

        $this->assertStringStartsWith('sha256:', $first);
        $this->assertSame($first, RulesetDigest::forDirectory($this->workDir . '/rules'));
    }

    public function testDigestChangesWhenAFileChanges(): void
    {
        $before = RulesetDigest::forDirectory($this->workDir . '/rules');
        file_put_contents($this->workDir . '/rules/lfi-os-files.data', "etc/networks\n");

        $this->assertNotSame($before, RulesetDigest::forDirectory($this->workDir . '/rules'));
    }

    /**
     * A skipped subdirectory would leave its contents outside the pin while the
     * digest still looked complete, so it aborts instead.
     */
    public function testSubdirectoryInTheRulesTreeAbortsRatherThanBeingSkipped(): void
    {
        mkdir($this->workDir . '/rules/nested', 0o755);
        file_put_contents($this->workDir . '/rules/nested/hidden.conf', "SecRule ARGS \"@rx y\" \"id:2\"\n");

        $this->expectException(CrsEngineException::class);
        $this->expectExceptionMessageMatches('/Unexpected subdirectory/');

        RulesetDigest::forDirectory($this->workDir . '/rules');
    }

    public function testEmptyRulesDirectoryIsAnError(): void
    {
        foreach (glob($this->workDir . '/rules/*') ?: [] as $file) {
            unlink($file);
        }

        $this->expectException(CrsEngineException::class);
        RulesetDigest::forDirectory($this->workDir . '/rules');
    }

    public function testHttpsSourceIsAccepted(): void
    {
        $crsFetcher = new CrsFetcher('https://github.com/coreruleset/coreruleset');

        $this->assertInstanceOf(CrsFetcher::class, $crsFetcher);
    }

    /**
     * @return \Iterator<string, array{string}>
     */
    public static function insecureSourceProvider(): \Iterator
    {
        yield 'plain http' => ['http://github.com/coreruleset/coreruleset'];
        yield 'file url' => ['file:///tmp/coreruleset'];
        yield 'scheme-relative' => ['//github.com/coreruleset/coreruleset'];
        yield 'bare host' => ['github.com/coreruleset/coreruleset'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('insecureSourceProvider')]
    public function testNonHttpsSourceIsRefused(string $source): void
    {
        $this->expectException(CrsEngineException::class);
        $this->expectExceptionMessageMatches('/must be an https URL/');

        new CrsFetcher($source);
    }
}

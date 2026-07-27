<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Parser;

use Kanopi\Crs\Parser\SecLangParser;
use PHPUnit\Framework\TestCase;

/**
 * @pmFromFile takes its filename from rule text, and bin/refresh-crs parses a
 * freshly downloaded CRS release, so the name is untrusted. A path or a symlink
 * must not be able to pull file contents into the compiled ruleset — the weekly
 * workflow commits that output to a public repository.
 */
final class PmFromFileContainmentTest extends TestCase
{
    private string $workDir;

    private string $outsideFile;

    protected function setUp(): void
    {
        $this->workDir = sys_get_temp_dir() . '/crs-pmf-containment-' . bin2hex(random_bytes(6));
        mkdir($this->workDir . '/rules', 0o755, true);

        // Stands in for anything readable outside the ruleset.
        $this->outsideFile = $this->workDir . '/secret.data';
        file_put_contents($this->outsideFile, "topsecret-phrase\nanother-secret\n");

        file_put_contents($this->workDir . '/rules/legit.data', "sleep\nbenchmark\n");
    }

    protected function tearDown(): void
    {
        foreach (['/rules/legit.data', '/rules/escape.data', '/secret.data'] as $relative) {
            $path = $this->workDir . $relative;
            if (is_link($path) || is_file($path)) {
                unlink($path);
            }
        }

        foreach ([$this->workDir . '/rules', $this->workDir] as $dir) {
            if (is_dir($dir)) {
                rmdir($dir);
            }
        }
    }

    /**
     * @return array<int, \Kanopi\Crs\Parser\ParsedRule>
     */
    private function parse(string $pmfArgument, SecLangParser $secLangParser): array
    {
        return $secLangParser->parseString(
            sprintf('SecRule ARGS "@pmFromFile %s" "id:5100,phase:2,block,t:none"', $pmfArgument),
            'REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
            $this->workDir . '/rules',
        );
    }

    public function testABareFilenameInTheDirectoryStillLoads(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $this->parse('legit.data', $secLangParser);

        $this->assertCount(1, $rules);
        $this->assertSame('pmf', $rules[0]->operator);
        $this->assertStringContainsString('benchmark', $rules[0]->operatorArgument);
        $this->assertSame([], $secLangParser->warnings);
    }

    /**
     * @return \Iterator<string, array{string}>
     */
    public static function traversalProvider(): \Iterator
    {
        yield 'parent traversal' => ['../secret.data'];
        yield 'deep traversal' => ['../../../../etc/passwd'];
        yield 'absolute path' => ['/etc/passwd'];
        yield 'subdirectory' => ['sub/legit.data'];
        yield 'dot-slash prefix' => ['./legit.data'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('traversalProvider')]
    public function testAPathIsRefusedRatherThanNormalised(string $argument): void
    {
        $secLangParser = new SecLangParser();
        $rules = $this->parse($argument, $secLangParser);

        $this->assertCount(0, $rules, 'A rule whose data file cannot be read must be dropped.');
        $this->assertNotEmpty($secLangParser->warnings);
        $this->assertStringContainsString(
            'not a bare filename',
            implode("\n", $secLangParser->warnings),
            'The refusal should be recorded specifically, not just as "unsupported operator".'
        );
    }

    public function testTraversalDoesNotLeakFileContentsIntoTheRule(): void
    {
        $secLangParser = new SecLangParser();
        $rules = $this->parse('../secret.data', $secLangParser);

        $this->assertSame([], $rules);
        $this->assertStringNotContainsString(
            'topsecret-phrase',
            implode("\n", array_map(
                static fn (\Kanopi\Crs\Parser\ParsedRule $parsedRule): string => $parsedRule->operatorArgument,
                $rules
            )) . implode("\n", $secLangParser->warnings),
            'Contents of a file outside the ruleset must never reach the compiled rules.'
        );
    }

    public function testASymlinkPointingOutsideTheDirectoryIsRefused(): void
    {
        $link = $this->workDir . '/rules/escape.data';
        if (!@symlink($this->outsideFile, $link)) {
            $this->markTestSkipped('Filesystem does not support symlinks here.');
        }

        $secLangParser = new SecLangParser();
        $rules = $this->parse('escape.data', $secLangParser);

        $this->assertSame([], $rules, 'A bare filename is not on its own proof the read stays inside.');
        $this->assertStringContainsString(
            'resolves outside',
            implode("\n", $secLangParser->warnings)
        );
    }

    public function testTheRealCrsDataFilesStillParse(): void
    {
        // Guards against the containment check being too strict for the real
        // ruleset, where @pmFromFile is used with plain sibling filenames.
        $secLangParser = new SecLangParser();
        $rules = $secLangParser->parseString(
            'SecRule ARGS "@pmFromFile pm-test.data" "id:5101,phase:2,block,t:lowercase"',
            'fixture.conf',
            __DIR__ . '/../../Integration/fixtures',
        );

        $this->assertCount(1, $rules);
        $this->assertStringContainsString('sleep', $rules[0]->operatorArgument);
        $this->assertSame([], $secLangParser->warnings);
    }
}

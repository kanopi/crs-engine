<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Refresh;

use Kanopi\Crs\Exception\CrsEngineException;
use Kanopi\Crs\Refresh\ReadmePin;
use PHPUnit\Framework\TestCase;

/**
 * The README quotes .crs-version to document the pin format, and ReadmeTest
 * asserts the shipped digest appears there. Keeping that copy correct by hand
 * did not work: every `--bump` moved the pin and left the README behind, which
 * failed the test inside the weekly refresh job and stopped it opening a PR.
 */
final class ReadmePinTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/crs-readme-pin-' . bin2hex(random_bytes(6)) . '.md';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testSyncRewritesThePinBlock(): void
    {
        $this->write(<<<'MD'
            ### Version pin format

            ```
            tag=v4.28.0
            sha=sha256:old
            source=https://github.com/coreruleset/coreruleset
            ```

            The `source` field can point at a fork or mirror.
            MD);

        $changed = (new ReadmePin($this->path))->sync([
            'tag'    => 'v4.29.0',
            'sha'    => 'sha256:new',
            'source' => 'https://github.com/coreruleset/coreruleset',
        ]);

        $this->assertTrue($changed);
        $readme = (string) file_get_contents($this->path);
        $this->assertStringContainsString("tag=v4.29.0\nsha=sha256:new\n", $readme);
        $this->assertStringNotContainsString('sha256:old', $readme);

        // Prose either side of the block must survive untouched.
        $this->assertStringContainsString('### Version pin format', $readme);
        $this->assertStringContainsString('point at a fork or mirror', $readme);
    }

    public function testSyncLeavesAnAlreadyCorrectReadmeAlone(): void
    {
        $this->write(<<<'MD'
            ```
            tag=v4.29.0
            sha=sha256:same
            source=https://github.com/coreruleset/coreruleset
            ```
            MD);

        $before = (string) file_get_contents($this->path);

        $changed = (new ReadmePin($this->path))->sync([
            'tag'    => 'v4.29.0',
            'sha'    => 'sha256:same',
            'source' => 'https://github.com/coreruleset/coreruleset',
        ]);

        $this->assertFalse($changed);
        $this->assertSame($before, (string) file_get_contents($this->path));
    }

    public function testSyncRewritesOnlyTheFirstPinBlock(): void
    {
        // Other fenced blocks in the README must not be mistaken for the pin.
        $this->write(<<<'MD'
            ```
            tag=v4.28.0
            sha=sha256:old
            source=https://github.com/coreruleset/coreruleset
            ```

            ```php
            $config = new CrsConfig();
            ```
            MD);

        (new ReadmePin($this->path))->sync([
            'tag'    => 'v4.29.0',
            'sha'    => 'sha256:new',
            'source' => 'https://github.com/coreruleset/coreruleset',
        ]);

        $readme = (string) file_get_contents($this->path);
        $this->assertStringContainsString('$config = new CrsConfig();', $readme);
        $this->assertSame(1, substr_count($readme, 'tag=v4.29.0'));
    }

    public function testMissingPinBlockIsFatal(): void
    {
        // A README that stopped quoting the pin would otherwise let the
        // refresh succeed while silently publishing a stale digest.
        $this->write("# crs-engine\n\nNo pin block here.\n");

        $this->expectException(CrsEngineException::class);
        $this->expectExceptionMessageMatches('/version pin block/');

        (new ReadmePin($this->path))->sync([
            'tag'    => 'v4.29.0',
            'sha'    => 'sha256:new',
            'source' => 'https://github.com/coreruleset/coreruleset',
        ]);
    }

    public function testMissingReadmeIsFatal(): void
    {
        $this->expectException(CrsEngineException::class);
        $this->expectExceptionMessageMatches('/Missing README/');

        (new ReadmePin($this->path))->sync([
            'tag'    => 'v4.29.0',
            'sha'    => 'sha256:new',
            'source' => 'https://github.com/coreruleset/coreruleset',
        ]);
    }

    private function write(string $contents): void
    {
        file_put_contents($this->path, $contents . "\n");
    }
}

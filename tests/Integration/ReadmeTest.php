<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * Keeps the README honest about what the engine actually does.
 *
 * Documentation drifted badly once already: it described a request-only
 * engine with no XML support long after both had shipped, and listed twenty
 * of the fifty-two variables the resolver implements. Prose can't be fully
 * checked by a test, but the claims that are mechanically checkable should
 * be — the ones that go stale are exactly the ones with numbers in them.
 */
final class ReadmeTest extends TestCase
{
    private function readme(): string
    {
        return (string) file_get_contents(dirname(__DIR__, 2) . '/README.md');
    }

    /**
     * @return array<int, string>
     */
    private function phpBlocks(): array
    {
        preg_match_all('/```php\n(.*?)```/s', $this->readme(), $m);

        return $m[1];
    }

    public function testReadmeContainsPhpExamples(): void
    {
        $this->assertNotEmpty($this->phpBlocks(), 'The extraction below silently passes if it finds nothing.');
    }

    /**
     * A example that does not parse has certainly rotted.
     */
    public function testEveryPhpExampleIsSyntacticallyValid(): void
    {
        foreach ($this->phpBlocks() as $i => $block) {
            $file = tempnam(sys_get_temp_dir(), 'crs-readme-') . '.php';
            file_put_contents($file, "<?php\n" . $block);

            $output = [];
            $status = 0;
            exec(sprintf('%s -l %s 2>&1', escapeshellarg(PHP_BINARY), escapeshellarg($file)), $output, $status);
            unlink($file);

            $this->assertSame(0, $status, sprintf("README PHP block #%d does not parse:\n%s", $i + 1, implode("\n", $output)));
        }
    }

    /**
     * Every class and method the README names in a fenced reference has to
     * exist. This is what caught the docs describing removed behaviour.
     */
    public function testReferencedApiExists(): void
    {
        $api = [
            \Kanopi\Crs\CrsEngine::class        => ['evaluate', 'evaluateResponse', 'ruleCount', 'crsVersion', 'ruleSet'],
            \Kanopi\Crs\CrsConfig::class        => ['inboundThreshold', 'outboundThreshold', 'severityScore', 'fromArray'],
            \Kanopi\Crs\CrsVerdict::class       => ['isBlocked', 'toArray'],
            \Kanopi\Crs\Request\RequestData::class => ['fromGlobals', 'header', 'allArgs', 'basename'],
        ];

        foreach ($api as $class => $methods) {
            $this->assertTrue(class_exists($class), $class . ' is referenced by the README but does not exist.');
            foreach ($methods as $method) {
                $this->assertTrue(
                    method_exists($class, $method),
                    sprintf('%s::%s() is referenced by the README but does not exist.', $class, $method),
                );
            }
        }
    }

    public function testDocumentedFilesAndDirectoriesExist(): void
    {
        $root = dirname(__DIR__, 2);

        foreach (['supplemental', 'rules', 'bin', 'src/Body', 'src/Refresh'] as $path) {
            $this->assertDirectoryExists($root . '/' . $path, $path . ' is documented in the project layout.');
        }

        foreach (['bin/refresh-crs', 'bin/crs-explain', '.crs-version'] as $path) {
            $this->assertFileExists($root . '/' . $path, $path . ' is documented in the project layout.');
        }
    }

    /**
     * The docs used to claim the engine parsed only request-side rules, long
     * after evaluateResponse() and the RESPONSE-* files had shipped.
     */
    public function testScopeSectionDoesNotClaimRequestOnly(): void
    {
        $readme = $this->readme();

        $this->assertStringNotContainsString(
            'response inspection is out of scope',
            $readme,
            'The engine parses RESPONSE-* rules; the scope section says otherwise.',
        );
        $this->assertStringContainsString('RESPONSE-951-DATA-LEAKAGES-SQL', $readme);
    }

    /**
     * Every variable the resolver implements should appear in the reference.
     * This is the check the old docs failed by 32 entries.
     */
    public function testEveryImplementedVariableIsDocumented(): void
    {
        $source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/Variables/VariableResolver.php');
        preg_match('/private function resolveOne.*?\n    }/s', $source, $m);
        $this->assertNotEmpty($m, 'Could not locate resolveOne(); this test needs updating.');

        preg_match_all("/'([A-Z][A-Z_0-9]{2,})'/", $m[0], $found);
        $implemented = array_unique(array_diff($found[1], ['UTF-8']));
        $this->assertGreaterThan(40, count($implemented), 'Suspiciously few variables found; the scrape is probably broken.');

        $readme = $this->readme();
        $undocumented = [];
        foreach ($implemented as $variable) {
            if (!str_contains($readme, '`' . $variable . '`')) {
                $undocumented[] = $variable;
            }
        }

        sort($undocumented);
        $this->assertSame([], $undocumented, 'These target variables are implemented but absent from the README.');
    }

    public function testOperatorAndTransformCountsAreAccurate(): void
    {
        $readme = $this->readme();

        $operators = count(glob(dirname(__DIR__, 2) . '/src/Operators/*Operator.php') ?: []);
        $transforms = count(glob(dirname(__DIR__, 2) . '/src/Transforms/*Transform.php') ?: []);

        $this->assertStringContainsString(sprintf('**Operators (%d):**', $operators), $readme);
        $this->assertStringContainsString(sprintf('**Transforms (%d):**', $transforms), $readme);
    }

    public function testShippedVersionPinIsTheOneDocumented(): void
    {
        $pin = parse_ini_file(dirname(__DIR__, 2) . '/.crs-version');
        $this->assertIsArray($pin);

        $this->assertStringContainsString(
            (string) $pin['sha'],
            $this->readme(),
            'The README shows a different content digest than .crs-version.',
        );
    }
}

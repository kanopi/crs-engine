<?php

declare(strict_types=1);

/**
 * Fail the build when coverage of the detection-critical directories drops.
 *
 * PHPUnit reports coverage but does not enforce a floor, and the code that has
 * actually shipped bypasses lives in two directories: src/Operators (a rule
 * decided the wrong thing) and src/Variables (a rule was handed the wrong
 * values). Both are small, so a floor there is cheap to hold and a new operator
 * arriving without a test is visible immediately.
 *
 * The thresholds are deliberately set just under current coverage rather than
 * at some aspirational round number: the point is to catch a regression, not to
 * generate work. Raise them when the real figure moves up.
 *
 * Usage:
 *   vendor/bin/phpunit --coverage-clover=build/clover.xml
 *   php tools/coverage-gate.php build/clover.xml
 */

/** @var array<string, int> Directory prefix (relative to project root) => minimum line coverage % */
const THRESHOLDS = [
    'src/Operators' => 90,
    'src/Variables' => 90,
    'src/Parser'    => 80,
    'src/Runtime'   => 80,
];

$cloverPath = $argv[1] ?? 'build/clover.xml';

if (!is_file($cloverPath)) {
    fwrite(STDERR, sprintf(
        "coverage-gate: no clover report at %s.\nRun: XDEBUG_MODE=coverage vendor/bin/phpunit --coverage-clover=%s\n",
        $cloverPath,
        $cloverPath,
    ));
    exit(1);
}

$xml = @simplexml_load_file($cloverPath);
if ($xml === false) {
    fwrite(STDERR, 'coverage-gate: could not parse ' . $cloverPath . "\n");
    exit(1);
}

$root = dirname(__DIR__);

/** @var array<string, array{covered: int, total: int}> $totals */
$totals = [];
foreach (array_keys(THRESHOLDS) as $prefix) {
    $totals[$prefix] = ['covered' => 0, 'total' => 0];
}

foreach ($xml->xpath('//file') ?: [] as $file) {
    $name = (string) $file['name'];
    $relative = str_starts_with($name, $root . '/') ? substr($name, strlen($root) + 1) : $name;

    foreach (array_keys(THRESHOLDS) as $prefix) {
        if (!str_starts_with($relative, $prefix . '/')) {
            continue;
        }

        // Statement lines only. Clover also emits method entries, which would
        // double-count a method against its own body.
        foreach ($file->line ?? [] as $line) {
            if ((string) $line['type'] !== 'stmt') {
                continue;
            }

            $totals[$prefix]['total']++;
            if ((int) $line['count'] > 0) {
                $totals[$prefix]['covered']++;
            }
        }
    }
}

$failed = false;
printf("%-18s %8s %8s  %s\n", 'directory', 'covered', 'floor', 'result');

foreach (THRESHOLDS as $prefix => $floor) {
    $total = $totals[$prefix]['total'];

    if ($total === 0) {
        printf("%-18s %8s %8d%%  %s\n", $prefix, 'n/a', $floor, 'NO DATA — is the path still right?');
        $failed = true;
        continue;
    }

    $percent = $totals[$prefix]['covered'] / $total * 100;
    $ok = $percent >= $floor;
    $failed = $failed || !$ok;

    printf("%-18s %7.1f%% %8d%%  %s\n", $prefix, $percent, $floor, $ok ? 'ok' : 'BELOW FLOOR');
}

if ($failed) {
    fwrite(STDERR, "\ncoverage-gate: coverage fell below the floor.\n"
        . "Add tests for the new code, or lower the threshold in tools/coverage-gate.php\n"
        . "with a note saying why.\n");
    exit(1);
}

echo "\ncoverage-gate: all directories at or above their floor.\n";
exit(0);

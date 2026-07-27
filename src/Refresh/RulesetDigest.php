<?php

declare(strict_types=1);

namespace Kanopi\Crs\Refresh;

use Kanopi\Crs\Exception\CrsEngineException;

/**
 * Content digest of a downloaded CRS release, used to detect a ruleset that
 * is not the one the pin expects.
 *
 * This hashes the *rule files*, not the release tarball. GitHub's
 * `/archive/refs/tags/` tarballs are generated on demand and are not
 * guaranteed byte-stable — when GitHub changed its gzip in 2023 every
 * auto-generated archive checksum changed at once and broke everyone pinning
 * them. Since bin/refresh-crs runs on a schedule in CI, a pin that can fail
 * for reasons unrelated to the content would train people to ignore it.
 *
 * Hashing the extracted files is stable across repacking and covers what we
 * actually care about: whether the rules are the rules we reviewed. It does
 * not authenticate the archive envelope, so it is a substitution check rather
 * than a signature — see the README.
 */
final class RulesetDigest
{
    /**
     * Canonical sha256 over every file in a CRS rules directory: one
     * `name:sha256` line per file, sorted by name, so the result depends only
     * on content and filenames.
     */
    public static function forDirectory(string $rulesPath): string
    {
        $files = glob(rtrim($rulesPath, '/') . '/*') ?: [];
        sort($files, SORT_STRING);

        $lines = [];
        foreach ($files as $file) {
            // The digest only covers the top level, which is all CRS has ever
            // shipped. Rather than skip a subdirectory silently — leaving its
            // contents outside the pin while the digest still looked complete —
            // refuse to produce a digest we know is partial. If upstream ever
            // nests rule files, this fails the refresh and gets looked at
            // instead of quietly under-hashing.
            if (is_dir($file)) {
                throw new CrsEngineException(sprintf(
                    'Unexpected subdirectory in the CRS rules tree: %s. The content digest covers '
                    . 'top-level files only, so it would not describe this. Extend RulesetDigest '
                    . 'to walk it and re-pin deliberately with --bump.',
                    $file,
                ));
            }

            if (!is_file($file)) {
                continue;
            }

            $hash = hash_file('sha256', $file);
            if ($hash === false) {
                throw new CrsEngineException('Could not hash rule file: ' . $file);
            }

            $lines[] = basename($file) . ':' . $hash;
        }

        if ($lines === []) {
            throw new CrsEngineException('No rule files to digest in ' . $rulesPath);
        }

        return 'sha256:' . hash('sha256', implode("\n", $lines));
    }
}

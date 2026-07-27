<?php

declare(strict_types=1);

namespace Kanopi\Crs\Refresh;

/**
 * Where a CRS release comes from.
 *
 * RefreshRunner depends on this rather than on CrsFetcher directly, so the
 * refresh flow — including digest verification and the failure paths — can be
 * exercised without network access, and so an integrator can substitute an
 * internal mirror or an already-vendored copy.
 */
interface CrsSource
{
    /**
     * Make the release available locally and return the path to its `rules/`
     * directory.
     *
     * @throws \Kanopi\Crs\Exception\CrsEngineException when the release cannot be obtained.
     */
    public function fetchTag(string $tag, string $workDir): string;

    /**
     * Resolve the newest stable release tag.
     *
     * @throws \Kanopi\Crs\Exception\CrsEngineException when the tag cannot be resolved.
     */
    public function latestTag(): string;
}

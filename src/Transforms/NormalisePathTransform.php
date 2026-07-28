<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * Collapses `.` and `..` segments and duplicate slashes, so LFI and RCE rules
 * match regardless of how the attacker writes the path.
 *
 * Named for the spelling CRS uses — `t:normalizePath`, with a z. The engine
 * previously registered only the British spelling, which nothing in the ruleset
 * ever writes, so the transform was dead code and the 12 rules asking for it
 * ran on unnormalised input. `normalisePath` is kept as an alias.
 *
 * A traversal that cannot be resolved is preserved, matching Apache's
 * ap_getparents() which ModSecurity follows: `../../etc/passwd` has no prior
 * segment to cancel, so it stays as it is. That distinction is load-bearing
 * here — the 930 rules match on `../` being present, and an earlier version of
 * this transform cancelled leading traversals against nothing, which would have
 * handed those rules a string with the evidence removed.
 *
 * An absolute path is the exception: `/../etc` cannot climb above the root, so
 * the segment is dropped rather than kept.
 */
class NormalisePathTransform implements TransformInterface
{
    public function name(): string
    {
        return 'normalizePath';
    }

    public function apply(string $value): string
    {
        if ($value === '') {
            return $value;
        }

        $absolute      = $value[0] === '/';
        $trailingSlash = str_ends_with($value, '/');

        $out = [];
        foreach (explode('/', $value) as $segment) {
            // Empty segments come from `//`; `.` is the current directory.
            if ($segment === '') {
                continue;
            }

            if ($segment === '.') {
                continue;
            }

            if ($segment !== '..') {
                $out[] = $segment;
                continue;
            }

            $last = $out === [] ? null : $out[count($out) - 1];

            // Something to cancel: drop the pair.
            if ($last !== null && $last !== '..') {
                array_pop($out);
                continue;
            }

            // Nothing to cancel. Above the root is nowhere, so an absolute path
            // discards it; a relative path keeps it, because `../x` genuinely
            // does refer to somewhere else and the rules want to see that.
            if (!$absolute) {
                $out[] = '..';
            }
        }

        $path = implode('/', $out);

        if ($absolute) {
            $path = '/' . $path;
        }

        if ($trailingSlash && $path !== '' && !str_ends_with($path, '/')) {
            $path .= '/';
        }

        return $path === '' ? ($absolute ? '/' : '') : $path;
    }
}

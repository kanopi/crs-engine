<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * Collapses path traversals (./, ../) and duplicate slashes so LFI rules
 * match regardless of how the attacker writes the path.
 *
 * Two things to know before relying on this.
 *
 * It is not currently reachable from the shipped ruleset. CRS spells the
 * transform `normalizePath`, with a z; this registers as `normalisePath`. The
 * names do not meet, so the 12 rules asking for it — the 930 LFI series, parts
 * of 932 and 933 — run on unnormalised input. SecLangParser reports that as an
 * unknown transform, and it is left reported rather than aliased because of
 * the next paragraph.
 *
 * It also diverges from ModSecurity on leading traversals. `../../etc/passwd`
 * comes out as `etc/passwd`, where normalizePath preserves a leading `../`
 * that has no prior segment to cancel. The loop below is happy to treat `..`
 * itself as the segment being cancelled. That matters here because the 930
 * rules match on the presence of `../`, so wiring up the alias without fixing
 * this would hand them a string with the evidence removed — turning a dormant
 * transform into a live regression.
 */
final class NormalisePathTransform implements TransformInterface
{
    public function name(): string
    {
        return 'normalisePath';
    }

    public function apply(string $value): string
    {
        $value = (string) preg_replace('#/+#', '/', $value);
        $value = (string) preg_replace('#/\./#', '/', $value);
        while (preg_match('#[^/]+/\.\./?#', $value)) {
            $value = (string) preg_replace('#[^/]+/\.\./?#', '', $value, 1);
        }

        return $value;
    }
}

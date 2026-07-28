<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

/**
 * `t:removeCommentsChar` — strip comment delimiters, keeping what is between
 * them.
 *
 * Distinct from removeComments, which removes the delimiters *and* the comment
 * body. This one exists so `SEL/*x*\/ECT` collapses to `SELECTx` rather than
 * `SELECT`, leaving the keyword visible to a rule that would otherwise be
 * evaded by splitting it.
 *
 * Delimiters, per ModSecurity: the SQL and C forms and the HTML pair.
 */
final class RemoveCommentsCharTransform implements TransformInterface
{
    private const DELIMITERS = ['/*', '*/', '<!--', '-->', '--', '#'];

    public function name(): string
    {
        return 'removeCommentsChar';
    }

    public function apply(string $value): string
    {
        return str_replace(self::DELIMITERS, '', $value);
    }
}

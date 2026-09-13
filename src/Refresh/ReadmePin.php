<?php

declare(strict_types=1);

namespace Kanopi\Crs\Refresh;

use Kanopi\Crs\Exception\CrsEngineException;

/**
 * Keeps the pin block quoted in README.md identical to .crs-version.
 *
 * The README documents the pin format by showing the real file, and
 * ReadmeTest asserts the shipped digest appears there. Nothing updated that
 * copy, so every successful `--bump` left the two disagreeing and failed the
 * test — which meant the weekly refresh job could never open a PR. Rewriting
 * the block from the pin file closes that loop: the quoted example cannot
 * drift because it is no longer maintained by hand.
 */
final class ReadmePin
{
    /**
     * The fenced block under "### Version pin format". Matched on its `tag=`
     * opening rather than on surrounding prose so that editing the section
     * text around it does not silently stop the sync.
     */
    private const BLOCK_PATTERN = '/^```\ntag=.*?\n```$/ms';

    public function __construct(private readonly string $path)
    {
    }

    /**
     * Rewrite the quoted pin block to match $pin. Returns true if the file
     * changed.
     *
     * @param array{tag: string, sha: string, source: string} $pin
     */
    public function sync(array $pin): bool
    {
        if (!is_file($this->path)) {
            throw new CrsEngineException('Missing README at ' . $this->path);
        }

        $readme = (string) file_get_contents($this->path);

        $block = sprintf(
            "```\ntag=%s\nsha=%s\nsource=%s\n```",
            $pin['tag'],
            $pin['sha'],
            $pin['source'],
        );

        $updated = preg_replace(self::BLOCK_PATTERN, $block, $readme, 1, $count);

        // A refresh that silently stopped documenting the pin is the exact
        // failure this class exists to prevent, so an unmatched block is
        // fatal rather than a no-op.
        if ($updated === null || $count === 0) {
            throw new CrsEngineException(sprintf(
                'Could not find the version pin block in %s. It must be a fenced block '
                . 'whose first line is `tag=`; see the "Version pin format" section.',
                $this->path,
            ));
        }

        if ($updated === $readme) {
            return false;
        }

        file_put_contents($this->path, $updated);

        return true;
    }
}

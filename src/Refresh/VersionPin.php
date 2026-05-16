<?php

declare(strict_types=1);

namespace Kanopi\Crs\Refresh;

use Kanopi\Crs\Exception\CrsEngineException;

/**
 * Read/write the .crs-version pin file.
 *
 * Format (one key=value per line):
 *   tag=v4.0.0
 *   sha=
 *   source=https://github.com/coreruleset/coreruleset
 */
final class VersionPin
{
    public function __construct(private readonly string $path)
    {
    }

    /**
     * @return array{tag: string, sha: string, source: string}
     */
    public function read(): array
    {
        if (!is_file($this->path)) {
            throw new CrsEngineException('Missing .crs-version at ' . $this->path);
        }

        $contents = (string) file_get_contents($this->path);
        $out = ['tag' => '', 'sha' => '', 'source' => 'https://github.com/coreruleset/coreruleset'];
        foreach (preg_split('/\r\n|\n|\r/', $contents) ?: [] as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            if (str_starts_with($line, '#')) {
                continue;
            }

            $eq = strpos($line, '=');
            if ($eq === false) {
                continue;
            }

            $key = strtolower(trim(substr($line, 0, $eq)));
            $val = trim(substr($line, $eq + 1));
            if (isset($out[$key])) {
                $out[$key] = $val;
            }
        }

        if ($out['tag'] === '') {
            throw new CrsEngineException(sprintf('Pin file %s has no tag set', $this->path));
        }

        return $out;
    }

    /**
     * @param array{tag: string, sha?: string, source?: string} $values
     */
    public function write(array $values): void
    {
        $current = is_file($this->path) ? $this->read() : ['tag' => '', 'sha' => '', 'source' => 'https://github.com/coreruleset/coreruleset'];
        $merged = array_merge($current, $values);
        $body = "tag={$merged['tag']}\nsha={$merged['sha']}\nsource={$merged['source']}\n";
        file_put_contents($this->path, $body);
    }
}

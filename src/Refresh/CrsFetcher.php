<?php

declare(strict_types=1);

namespace Kanopi\Crs\Refresh;

use Kanopi\Crs\Exception\CrsEngineException;

/**
 * Fetches an OWASP CRS release from GitHub and extracts it to a working
 * directory. Uses only PHP core (streams + PharData) to avoid composer deps.
 */
final class CrsFetcher implements CrsSource
{
    /**
     * Redirect hops to follow. GitHub bounces the archive URL to codeload, so
     * some redirection is required; an unbounded chain is not. PHP's default is
     * 20, which is 19 more than this needs.
     */
    private const MAX_REDIRECTS = 5;

    /**
     * @param string $source Repository URL to fetch releases from. Must be
     *        https: this is the only channel authenticating the ruleset — the
     *        content digest detects substitution between two fetches but cannot
     *        establish the publisher, and there is no signature check. Fetching
     *        rules over a channel anyone can rewrite would leave nothing at all
     *        standing behind them.
     */
    public function __construct(
        private readonly string $source = 'https://github.com/coreruleset/coreruleset',
        private readonly int $timeoutSeconds = 60,
    ) {
        if (!str_starts_with(strtolower($source), 'https://')) {
            throw new CrsEngineException(sprintf(
                'CRS source must be an https URL, got %s. To use a ruleset from elsewhere, '
                . 'extract it yourself and point CrsConfig::$rulesPath at the result.',
                $source,
            ));
        }
    }

    /**
     * Download CRS at the given tag and extract to $workDir. Returns the
     * path to the `rules/` directory inside the extracted release.
     */
    public function fetchTag(string $tag, string $workDir): string
    {
        if (!is_dir($workDir) && !mkdir($workDir, 0755, true) && !is_dir($workDir)) {
            throw new CrsEngineException('Could not create work dir: ' . $workDir);
        }

        $url = sprintf('%s/archive/refs/tags/%s.tar.gz', $this->source, $tag);
        $tar = $workDir . '/crs-' . $tag . '.tar.gz';

        $this->download($url, $tar);
        $this->extract($tar, $workDir);

        $stripped = ltrim($tag, 'v');
        $candidates = [
            $workDir . '/coreruleset-' . $stripped,
            $workDir . '/coreruleset-' . $tag,
        ];
        foreach ($candidates as $candidate) {
            if (is_dir($candidate . '/rules')) {
                return $candidate . '/rules';
            }
        }

        $found = glob($workDir . '/coreruleset-*/rules', GLOB_ONLYDIR) ?: [];
        if ($found !== []) {
            return $found[0];
        }

        throw new CrsEngineException("Extracted CRS archive but couldn't find rules/ directory in " . $workDir);
    }

    /**
     * Resolve the latest stable CRS release tag using GitHub's API.
     */
    public function latestTag(): string
    {
        $apiUrl = preg_replace('#^https?://github\.com/#', 'https://api.github.com/repos/', $this->source) . '/releases/latest';

        $context = stream_context_create([
            'http' => [
                'method'  => 'GET',
                'header'  => [
                    'User-Agent: kanopi-crs-engine',
                    'Accept: application/vnd.github+json',
                ],
                'timeout' => $this->timeoutSeconds,
            ],
        ]);

        $body = @file_get_contents($apiUrl, false, $context);
        if ($body === false) {
            throw new CrsEngineException('Could not fetch latest release info from ' . $apiUrl);
        }

        $data = json_decode($body, true);
        if (!is_array($data) || !isset($data['tag_name'])) {
            throw new CrsEngineException('Malformed GitHub release payload');
        }

        return (string) $data['tag_name'];
    }

    private function download(string $url, string $destination): void
    {
        $context = stream_context_create([
            'http' => [
                'method'  => 'GET',
                'header'  => ['User-Agent: kanopi-crs-engine'],
                'timeout' => $this->timeoutSeconds,
                'follow_location' => 1,
                'max_redirects'   => self::MAX_REDIRECTS,
            ],
        ]);
        $data = @file_get_contents($url, false, $context);
        if ($data === false) {
            throw new CrsEngineException('Failed to download ' . $url);
        }

        file_put_contents($destination, $data);
    }

    private function extract(string $tarGz, string $workDir): void
    {
        $tarPath = preg_replace('/\.gz$/', '', $tarGz) ?: $tarGz;
        try {
            $phar = new \PharData($tarGz);
            $phar->decompress();
            $phar2 = new \PharData($tarPath);
            $phar2->extractTo($workDir, null, true);
        } catch (\Throwable $throwable) {
            throw new CrsEngineException('Failed to extract CRS archive: ' . $throwable->getMessage(), 0, $throwable);
        }
    }
}

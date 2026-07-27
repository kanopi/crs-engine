<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

/**
 * A prepared phrase list for @pm / @pmf.
 *
 * Real ModSecurity uses Aho-Corasick. A plain loop over the list was good
 * enough until the profile showed otherwise: CRS ships lists of several
 * hundred to a couple of thousand phrases, and @pmf accounted for ~14% of
 * request time and over half of response time.
 *
 * Two exact filters do most of the work of an automaton here. Neither can
 * skip a phrase that could match:
 *
 *   1. A phrase longer than the subject cannot occur in it.
 *   2. A phrase can only occur if its first byte occurs in the subject.
 *
 * On short argument values — most of what a WAF inspects — that leaves a
 * small fraction of the list to test with str_contains.
 *
 * A PCRE alternation was tried instead and rejected: chunked into patterns
 * small enough to compile, it was roughly twice as slow as this on a 105 KB
 * body. (An unchunked alternation appears far faster only because PCRE fails
 * to compile it at all and returns immediately, which is easy to mistake for
 * a result.) Beating this properly needs a real Aho-Corasick automaton.
 */
final class PhraseSet
{
    /** @var array<int, array<int, string>> first byte => phrases starting with it */
    private array $byFirstByte = [];

    private int $shortest = PHP_INT_MAX;

    private bool $empty = true;

    /**
     * @param array<int, string> $phrases Already lowercased and non-empty.
     */
    private function __construct(array $phrases)
    {
        foreach ($phrases as $phrase) {
            $this->byFirstByte[ord($phrase[0])][] = $phrase;
            $this->shortest = min($this->shortest, strlen($phrase));
            $this->empty = false;
        }
    }

    /**
     * Split on whitespace — @pm's format.
     */
    public static function fromWhitespaceList(string $argument): self
    {
        return self::build(preg_split('/\s+/', trim($argument)) ?: []);
    }

    /**
     * Split on newlines — @pmf's format, which preserves phrases containing
     * spaces such as "Mozilla/5.0 (compatible; Panoptic".
     */
    public static function fromLines(string $argument): self
    {
        return self::build(preg_split('/\r\n|\n|\r/', $argument) ?: []);
    }

    /**
     * @param array<int, string> $raw
     */
    private static function build(array $raw): self
    {
        $phrases = [];
        foreach ($raw as $line) {
            $line = strtolower(trim($line));
            if ($line !== '') {
                $phrases[] = $line;
            }
        }

        return new self($phrases);
    }

    /**
     * The first phrase occurring in $subject, or null.
     */
    public function firstMatch(string $subject): ?string
    {
        $length = strlen($subject);
        if ($this->empty || $length === 0 || $length < $this->shortest) {
            return null;
        }

        $subject = strtolower($subject);

        // Byte histogram of the subject; a phrase whose first byte is absent
        // cannot occur, so its whole bucket is skipped.
        $present = count_chars($subject, 1);

        foreach ($this->byFirstByte as $byte => $phrases) {
            if (!isset($present[$byte])) {
                continue;
            }

            foreach ($phrases as $phrase) {
                if (strlen($phrase) > $length) {
                    continue;
                }

                if (str_contains($subject, $phrase)) {
                    return $phrase;
                }
            }
        }

        return null;
    }
}

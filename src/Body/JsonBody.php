<?php

declare(strict_types=1);

namespace Kanopi\Crs\Body;

use Kanopi\Crs\Request\RequestData;

/**
 * Flattens a JSON request body into ARGS, the way ModSecurity's JSON body
 * processor does.
 *
 * Almost every CRS detection rule targets ARGS — 187 of them — while only 19
 * look at REQUEST_BODY as raw text, and not one targets ARGS_POST. So a JSON
 * body that never reaches ARGS is a body the ruleset barely inspects. Measured
 * across seven attack payloads in a JSON body, the engine blocked 1 of 7
 * without this and 7 of 7 with it.
 *
 * This is a fallback, not a replacement. An integrator who supplies postArgs
 * has already parsed the body with the same parser the application will use,
 * and that matters: a WAF that parses JSON differently from the application
 * creates a parser differential, where the attacker arranges for the two to
 * disagree and the WAF inspects something the application never sees. So
 * postArgs wins whenever it is populated, and this only fills the gap where
 * nothing did — which was previously silent.
 *
 * Naming follows ModSecurity: a `json.` prefix and dot-joined path, so
 * `{"user":{"name":"x"}}` becomes `ARGS:json.user.name` and array elements take
 * their index. Exclusions written against upstream variable names therefore
 * still mean something here.
 */
final class JsonBody
{
    /**
     * Nesting depth handed to json_decode. Well beyond any real payload, and
     * far below the point where recursion is the problem.
     */
    private const MAX_DEPTH = 64;

    /** @var array<string, string>|null */
    private ?array $args = null;

    private bool $attempted = false;

    private bool $failed = false;

    /**
     * @param int $maxBytes Bodies larger than this are not parsed at all.
     *        Truncated JSON is not JSON, so there is nothing to gain by trying.
     * @param int $maxEntries Ceiling on flattened arguments, so a deeply
     *        branching document cannot turn one request into unbounded work
     *        before the argument caps in VariableResolver get a chance to apply.
     */
    public function __construct(
        private readonly RequestData $requestData,
        private readonly int $maxBytes,
        private readonly int $maxEntries = 5000,
    ) {
    }

    /**
     * Whether this body is worth trying to parse as JSON. Content-Type first,
     * then the shape of the body, mirroring XmlBody::isLikelyXml().
     */
    public function isLikelyJson(): bool
    {
        $body = ltrim($this->requestData->body);
        if ($body === '') {
            return false;
        }

        $contentType = strtolower((string) $this->requestData->header('Content-Type'));
        if ($contentType !== '' && str_contains($contentType, 'json')) {
            return true;
        }

        return $body[0] === '{' || $body[0] === '[';
    }

    /**
     * True when the body looked like JSON and could not be parsed.
     *
     * Worth surfacing rather than swallowing: a malformed body means the
     * ruleset saw none of it as arguments, which is a coverage gap and not the
     * same thing as a clean request.
     */
    public function failedToParse(): bool
    {
        $this->parse();

        return $this->failed;
    }

    /**
     * @return array<string, string> Flattened `json.path` => value
     */
    public function args(): array
    {
        $this->parse();

        return $this->args ?? [];
    }

    private function parse(): void
    {
        if ($this->attempted) {
            return;
        }

        $this->attempted = true;

        if ($this->requestData->body === '' || !$this->isLikelyJson()) {
            return;
        }

        if ($this->maxBytes >= 0 && strlen($this->requestData->body) > $this->maxBytes) {
            // Not a parse failure — a deliberate refusal, reported separately by
            // the resolver as a truncation.
            return;
        }

        try {
            $decoded = json_decode($this->requestData->body, true, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            $this->failed = true;
            return;
        }

        // A bare scalar is valid JSON but has no structure to flatten; the raw
        // body is still inspected via REQUEST_BODY.
        if (!is_array($decoded)) {
            return;
        }

        $out = [];
        $this->flatten($decoded, 'json', $out);
        $this->args = $out;
    }

    /**
     * @param array<array-key, mixed> $value
     * @param array<string, string> $out
     */
    private function flatten(array $value, string $prefix, array &$out): void
    {
        foreach ($value as $key => $item) {
            if (count($out) >= $this->maxEntries) {
                return;
            }

            $path = $prefix . '.' . $key;

            if (is_array($item)) {
                $this->flatten($item, $path, $out);
                continue;
            }

            $out[$path] = $this->stringify($item);
        }
    }

    private function stringify(mixed $value): string
    {
        if (is_string($value)) {
            return $value;
        }

        if ($value === null) {
            return '';
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        return is_scalar($value) ? (string) $value : '';
    }
}

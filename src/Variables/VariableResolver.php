<?php

declare(strict_types=1);

namespace Kanopi\Crs\Variables;

use Kanopi\Crs\Body\XmlBody;
use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Request\ResponseData;
use Kanopi\Crs\Runtime\TxStore;

/**
 * Resolves a parsed target expression (e.g. ARGS, REQUEST_HEADERS:User-Agent,
 * !ARGS:csrf_token) against a RequestData into a flat list of ResolvedValue.
 *
 * Targets are pre-parsed by the rule parser into a normalised form:
 *   ['collection' => 'ARGS', 'selector' => null,    'negated' => false, 'count' => false]
 *   ['collection' => 'REQUEST_HEADERS', 'selector' => 'User-Agent', ...]
 *   ['collection' => '&ARGS', ...]  // count form
 */
final class VariableResolver
{
    private ?XmlBody $xmlBody = null;

    /**
     * Resolved collections for this request.
     *
     * resolve() runs once per rule — 237 times for a ten-argument request
     * against the shipped ruleset — and each call re-walked the same argument
     * bags from scratch. The request cannot change mid-run, so a collection
     * only has to be built once.
     *
     * TX is deliberately excluded: setvar mutates it as rules fire, so its
     * values must be read live.
     *
     * @var array<string, array<int, ResolvedValue>>
     */
    private array $collectionCache = [];

    /**
     * Argument collections, whose value enumeration is capped. Counting is not:
     * see resolve().
     *
     * @var array<int, string>
     */
    private const ARG_COLLECTIONS = [
        'ARGS', 'ARGS_GET', 'ARGS_POST',
        'ARGS_NAMES', 'ARGS_GET_NAMES', 'ARGS_POST_NAMES',
    ];

    /**
     * What this request had inspection cut short on, keyed so a repeat from a
     * later rule does not report twice.
     *
     * @var array<string, array{what: string, inspected: int, total: int}>
     */
    private array $truncations = [];

    /**
     * @param int $maxArgs Argument values to enumerate, or CrsConfig::UNLIMITED.
     *        Defaults to unbounded here rather than to the CrsConfig default,
     *        so a resolver constructed directly — as tests do — behaves as it
     *        always has. CrsEngine supplies the configured values.
     * @param int $maxRequestBodyBytes Request body bytes to expose, or
     *        CrsConfig::UNLIMITED.
     * @param int $maxArgBytes Total argument bytes per resolve() call, or
     *        CrsConfig::UNLIMITED.
     * @param int $maxResponseBodyBytes Response body bytes to expose, or
     *        CrsConfig::UNLIMITED. Separate from the request limit: a 128 KB
     *        request body is large, a 128 KB HTML page is ordinary, and capping
     *        both at the request figure hid the tail of normal pages from the
     *        response-phase rules.
     */
    public function __construct(
        private readonly TxStore $txStore,
        private readonly ?ResponseData $responseData = null,
        private readonly int $maxArgs = CrsConfig::UNLIMITED,
        private readonly int $maxRequestBodyBytes = CrsConfig::UNLIMITED,
        private readonly int $maxArgBytes = CrsConfig::UNLIMITED,
        private readonly int $maxResponseBodyBytes = CrsConfig::UNLIMITED,
    ) {
    }

    /**
     * Where inspection was cut short for this request. Empty when everything
     * was seen.
     *
     * @return array<int, array{what: string, inspected: int, total: int}>
     */
    public function truncations(): array
    {
        return array_values($this->truncations);
    }

    /**
     * @param array<int, array{collection: string, selector?: ?string, negated?: bool, count?: bool, regex?: bool}> $targets
     * @return array<int, ResolvedValue>
     */
    public function resolve(array $targets, RequestData $requestData): array
    {
        $resolved = [];
        $excluded = [];

        foreach ($targets as $target) {
            $collection = $target['collection'];
            $selector   = $target['selector'] ?? null;
            $negated    = $target['negated'] ?? false;
            $count      = $target['count'] ?? false;
            $regex      = $target['regex'] ?? false;

            $values = $this->resolveCached($collection, $selector, $regex, $requestData);

            if ($negated) {
                foreach ($values as $value) {
                    $excluded[$value->location] = true;
                }

                continue;
            }

            // Counting is never capped. CRS 920380 blocks on `&ARGS` exceeding
            // tx.max_num_args, so if the cap fed it a truncated count the very
            // rule that flags an over-large request would stop firing — and the
            // truncation would then be a silent detection loss instead of a
            // flagged one.
            if ($count) {
                $resolved[] = new ResolvedValue('&' . $collection . ($selector ? ':' . $selector : ''), (string) count($values));
                continue;
            }

            $values = $this->capArgValues($collection, $values);

            foreach ($values as $value) {
                $resolved[] = $value;
            }
        }

        if ($excluded === []) {
            return $resolved;
        }

        return array_values(array_filter(
            $resolved,
            static fn (ResolvedValue $resolvedValue): bool => !isset($excluded[$resolvedValue->location])
        ));
    }

    /**
     * Limit how many argument values go through the ruleset.
     *
     * Unbounded, cost is linear in the argument count with a large constant —
     * 5,000 arguments in a 130 KB body took 2.2s of CPU against the shipped
     * ruleset, versus 26ms for an ordinary request. The request is blocked, but
     * only after the work is done, which makes it cheap amplification against a
     * fixed worker pool.
     *
     * @param array<int, ResolvedValue> $values
     * @return array<int, ResolvedValue>
     */
    private function capArgValues(string $collection, array $values): array
    {
        if (!in_array(strtoupper($collection), self::ARG_COLLECTIONS, true)) {
            return $values;
        }

        if ($this->maxArgs !== CrsConfig::UNLIMITED && count($values) > $this->maxArgs) {
            $this->recordTruncation('args', $this->maxArgs, count($values));
            $values = array_slice($values, 0, $this->maxArgs);
        }

        return $this->capArgBytes($values);
    }

    /**
     * Spend a byte budget across the argument values, truncating the one that
     * crosses it and dropping the rest.
     *
     * The count cap alone does not bound the work: a single 2.5 MB argument
     * costs about what ten thousand small ones do, because the expense is bytes
     * scanned per rule rather than values iterated. Both ceilings are needed.
     *
     * @param array<int, ResolvedValue> $values
     * @return array<int, ResolvedValue>
     */
    private function capArgBytes(array $values): array
    {
        if ($this->maxArgBytes === CrsConfig::UNLIMITED) {
            return $values;
        }

        $total = 0;
        foreach ($values as $value) {
            $total += strlen($value->value);
        }

        if ($total <= $this->maxArgBytes) {
            return $values;
        }

        $this->recordTruncation('arg_bytes', $this->maxArgBytes, $total);

        $remaining = $this->maxArgBytes;
        $out       = [];
        foreach ($values as $value) {
            $length = strlen($value->value);

            if ($length <= $remaining) {
                $out[]      = $value;
                $remaining -= $length;
                continue;
            }

            // Keep a prefix of the value that crosses the budget rather than
            // dropping it whole: a payload at the front of an oversized
            // argument is still worth catching.
            if ($remaining > 0) {
                $out[] = new ResolvedValue($value->location, substr($value->value, 0, $remaining));
            }

            break;
        }

        return $out;
    }

    /**
     * Limit how much of a body the ruleset sees. Cost is linear in body size,
     * and every byte is attacker-controlled.
     */
    private function capBody(string $what, string $body, int $limit): string
    {
        if ($limit === CrsConfig::UNLIMITED) {
            return $body;
        }

        $length = strlen($body);
        if ($length <= $limit) {
            return $body;
        }

        $this->recordTruncation($what, $limit, $length);

        return substr($body, 0, $limit);
    }

    private function recordTruncation(string $what, int $inspected, int $total): void
    {
        // Keyed by kind: the same cap is hit by every rule targeting the same
        // collection, and reporting it 200 times says nothing extra.
        $this->truncations[$what] = ['what' => $what, 'inspected' => $inspected, 'total' => $total];
    }

    /**
     * @return array<int, ResolvedValue>
     */
    private function resolveCached(string $collection, ?string $selector, bool $selectorIsRegex, RequestData $requestData): array
    {
        if (strtoupper($collection) === 'TX') {
            return $this->resolveOne($collection, $selector, $selectorIsRegex, $requestData);
        }

        $key = $collection . '|' . ($selector ?? '') . '|' . ($selectorIsRegex ? '1' : '0');

        return $this->collectionCache[$key]
            ??= $this->resolveOne($collection, $selector, $selectorIsRegex, $requestData);
    }

    /**
     * @return array<int, ResolvedValue>
     */
    private function resolveOne(string $collection, ?string $selector, bool $selectorIsRegex, RequestData $requestData): array
    {
        return match (strtoupper($collection)) {
            // ARGS is the concatenation of the query and body bags, not a merge
            // of them. Resolving it from a name-keyed union (RequestData::allArgs())
            // dropped the POST value whenever a query parameter of the same name
            // existed, so `?id=harmless` with the payload in POST:id evaluated as
            // if the payload were not there — a bypass of every ARGS rule, which
            // is most of the ruleset. Same-named parameters are distinct values
            // here, exactly as they are in ModSecurity.
            'ARGS'             => array_merge(
                $this->flatten('ARGS', $requestData->queryArgs, $selector, $selectorIsRegex),
                $this->flatten('ARGS', $requestData->postArgs, $selector, $selectorIsRegex),
            ),
            'ARGS_GET'         => $this->flatten('ARGS_GET', $requestData->queryArgs, $selector, $selectorIsRegex),
            'ARGS_POST'        => $this->flatten('ARGS_POST', $requestData->postArgs, $selector, $selectorIsRegex),
            'ARGS_NAMES'       => array_merge(
                $this->keys('ARGS_NAMES', $requestData->queryArgs, $selector, $selectorIsRegex),
                $this->keys('ARGS_NAMES', $requestData->postArgs, $selector, $selectorIsRegex),
            ),
            'ARGS_GET_NAMES'   => $this->keys('ARGS_GET_NAMES', $requestData->queryArgs, $selector, $selectorIsRegex),
            'ARGS_POST_NAMES'  => $this->keys('ARGS_POST_NAMES', $requestData->postArgs, $selector, $selectorIsRegex),
            'REQUEST_HEADERS'  => $this->flattenHeaders('REQUEST_HEADERS', $requestData->headers, $selector, $selectorIsRegex),
            'REQUEST_HEADERS_NAMES' => $this->keys('REQUEST_HEADERS_NAMES', $requestData->headers, $selector, $selectorIsRegex),
            'REQUEST_COOKIES'  => $this->flatten('REQUEST_COOKIES', $requestData->cookies, $selector, $selectorIsRegex),
            'REQUEST_COOKIES_NAMES' => $this->keys('REQUEST_COOKIES_NAMES', $requestData->cookies, $selector, $selectorIsRegex),
            'REQUEST_URI'      => [new ResolvedValue('REQUEST_URI', $requestData->uri)],
            'REQUEST_URI_RAW'  => [new ResolvedValue('REQUEST_URI_RAW', $requestData->rawUri)],
            'REQUEST_FILENAME' => [new ResolvedValue('REQUEST_FILENAME', $this->filename($requestData->uri))],
            'REQUEST_BASENAME' => [new ResolvedValue('REQUEST_BASENAME', $requestData->basename())],
            'REQUEST_METHOD'   => [new ResolvedValue('REQUEST_METHOD', $requestData->method)],
            'REQUEST_PROTOCOL' => [new ResolvedValue('REQUEST_PROTOCOL', $requestData->protocol)],
            'REQUEST_LINE'     => [new ResolvedValue('REQUEST_LINE', sprintf('%s %s %s', $requestData->method, $requestData->uri, $requestData->protocol))],
            'REQUEST_BODY'     => [new ResolvedValue('REQUEST_BODY', $this->capBody('request_body', $requestData->body, $this->maxRequestBodyBytes))],
            'QUERY_STRING'     => [new ResolvedValue('QUERY_STRING', $requestData->queryString)],
            'REMOTE_ADDR'      => [new ResolvedValue('REMOTE_ADDR', $requestData->remoteAddr)],
            'UNIQUE_ID'        => $requestData->uniqueId === null ? [] : [new ResolvedValue('UNIQUE_ID', $requestData->uniqueId)],
            'REQBODY_PROCESSOR' => $requestData->bodyProcessor === null ? [] : [new ResolvedValue('REQBODY_PROCESSOR', $requestData->bodyProcessor)],
            'FILES_NAMES'      => $this->fileNames($requestData->files),
            'FILES'            => $this->fileContents($requestData->files),
            'FILES_TMPNAMES'   => $this->fileTmpNames($requestData->files),
            'FILES_SIZES'      => $this->fileSizes($requestData->files),
            'XML'              => $this->xmlValues($selector ?? '/*', $requestData),
            'RESPONSE_STATUS'  => $this->responseData instanceof \Kanopi\Crs\Request\ResponseData ? [new ResolvedValue('RESPONSE_STATUS', (string) $this->responseData->status)] : [],
            'RESPONSE_PROTOCOL' => $this->responseData instanceof \Kanopi\Crs\Request\ResponseData ? [new ResolvedValue('RESPONSE_PROTOCOL', $this->responseData->protocol)] : [],
            'RESPONSE_HEADERS' => $this->responseData instanceof \Kanopi\Crs\Request\ResponseData ? $this->flattenHeaders('RESPONSE_HEADERS', $this->responseData->headers, $selector, $selectorIsRegex) : [],
            'RESPONSE_HEADERS_NAMES' => $this->responseData instanceof \Kanopi\Crs\Request\ResponseData ? $this->keys('RESPONSE_HEADERS_NAMES', $this->responseData->headers, $selector, $selectorIsRegex) : [],
            'RESPONSE_BODY'    => $this->responseData instanceof \Kanopi\Crs\Request\ResponseData ? [new ResolvedValue('RESPONSE_BODY', $this->capBody('response_body', $this->responseData->body, $this->maxResponseBodyBytes))] : [],
            'RESPONSE_CONTENT_TYPE' => $this->responseData instanceof \Kanopi\Crs\Request\ResponseData ? [new ResolvedValue('RESPONSE_CONTENT_TYPE', $this->responseData->effectiveContentType())] : [],
            'RESPONSE_CONTENT_LENGTH' => $this->responseData instanceof \Kanopi\Crs\Request\ResponseData ? [new ResolvedValue('RESPONSE_CONTENT_LENGTH', (string) $this->responseData->bodyLength())] : [],
            'OUTBOUND_DATA_ERROR' => $this->responseData instanceof \Kanopi\Crs\Request\ResponseData ? [new ResolvedValue('OUTBOUND_DATA_ERROR', $this->responseData->status >= 500 ? '1' : '0')] : [],
            'MULTIPART_PART_HEADERS' => $this->multipartHeaders($requestData->multipartPartHeaders),
            'MULTIPART_STRICT_ERROR', 'MULTIPART_UNMATCHED_BOUNDARY',
            'MULTIPART_BOUNDARY_QUOTED', 'MULTIPART_BOUNDARY_WHITESPACE',
            'MULTIPART_CRLF_LF_LINES', 'MULTIPART_DATA_AFTER',
            'MULTIPART_DATA_BEFORE', 'MULTIPART_FILE_LIMIT_EXCEEDED',
            'MULTIPART_HEADER_FOLDING', 'MULTIPART_INVALID_HEADER_FOLDING',
            'MULTIPART_INVALID_PART', 'MULTIPART_INVALID_QUOTING',
            'MULTIPART_LF_LINE', 'MULTIPART_MISSING_SEMICOLON',
            'MULTIPART_NAME', 'MULTIPART_SEMICOLON_MISSING' => $this->multipartFlag($collection, $requestData->multipartFlags),
            'TX'               => $this->txValues($selector, $selectorIsRegex),
            default            => [],
        };
    }

    /**
     * @param array<string|int, mixed> $bag
     * @return array<int, ResolvedValue>
     */
    private function flatten(string $collection, array $bag, ?string $selector, bool $isRegex): array
    {
        $out = [];
        foreach ($bag as $key => $value) {
            $strKey = (string) $key;
            if (!$this->matchesSelector($strKey, $selector, $isRegex)) {
                continue;
            }

            if (is_array($value)) {
                foreach ($this->flattenNested($value) as $subKey => $subValue) {
                    $out[] = new ResolvedValue(sprintf('%s:%s.%s', $collection, $strKey, $subKey), $subValue);
                }
            } else {
                $out[] = new ResolvedValue(sprintf('%s:%s', $collection, $strKey), $this->stringify($value));
            }
        }

        return $out;
    }

    /**
     * Coerce a resolved value to the string an operator will see.
     *
     * The bags arrive from an integrator's framework, so their leaf types are
     * whatever that framework produced — string, int, bool, null, or an object
     * with __toString(). A bare (string) cast fatals on anything else, and a
     * fatal here is a request the WAF failed open on, so the unrepresentable
     * cases serialise instead of throwing.
     */
    private function stringify(mixed $value): string
    {
        if (is_string($value)) {
            return $value;
        }

        if ($value === null) {
            return '';
        }

        if (is_scalar($value) || $value instanceof \Stringable) {
            return (string) $value;
        }

        return json_encode($value) ?: '';
    }

    /**
     * @param array<string|int, mixed> $bag
     * @return array<int, ResolvedValue>
     */
    private function flattenHeaders(string $collection, array $bag, ?string $selector, bool $isRegex): array
    {
        $out = [];
        foreach ($bag as $key => $value) {
            $strKey = (string) $key;
            if (!$this->matchesSelector($strKey, $selector, $isRegex, caseInsensitive: true)) {
                continue;
            }

            if (is_array($value)) {
                foreach ($value as $sub) {
                    $out[] = new ResolvedValue(sprintf('%s:%s', $collection, $strKey), $this->stringify($sub));
                }
            } else {
                $out[] = new ResolvedValue(sprintf('%s:%s', $collection, $strKey), $this->stringify($value));
            }
        }

        return $out;
    }

    /**
     * @param array<string|int, mixed> $bag
     * @return array<int, ResolvedValue>
     */
    private function keys(string $collection, array $bag, ?string $selector, bool $isRegex): array
    {
        $out = [];
        foreach (array_keys($bag) as $key) {
            $strKey = (string) $key;
            if (!$this->matchesSelector($strKey, $selector, $isRegex)) {
                continue;
            }

            $out[] = new ResolvedValue(sprintf('%s:%s', $collection, $strKey), $strKey);
        }

        return $out;
    }

    /**
     * @param array<int, array{name: string, filename: string}> $files
     * @return array<int, ResolvedValue>
     */
    private function fileNames(array $files): array
    {
        $out = [];
        foreach ($files as $file) {
            $out[] = new ResolvedValue('FILES_NAMES:' . $file['name'], $file['filename']);
        }

        return $out;
    }

    /**
     * FILES — actual upload contents. Reads from the upload's tmp_name path
     * if provided, falling back to inline `content` if the caller pre-read it
     * (e.g. into Redis). Returns empty if neither is available; the rule simply
     * doesn't fire.
     *
     * @param array<int, array{name: string, filename?: string, tmp_name?: string, content?: string}> $files
     * @return array<int, ResolvedValue>
     */
    private function fileContents(array $files): array
    {
        $out = [];
        foreach ($files as $file) {
            $content = $file['content'] ?? null;
            if ($content === null && isset($file['tmp_name']) && $file['tmp_name'] !== '' && is_readable($file['tmp_name'])) {
                $content = (string) file_get_contents($file['tmp_name']);
            }

            if ($content === null) {
                continue;
            }

            $out[] = new ResolvedValue('FILES:' . $file['name'], $content);
        }

        return $out;
    }

    /**
     * @param array<int, array{name: string, tmp_name?: string}> $files
     * @return array<int, ResolvedValue>
     */
    private function fileTmpNames(array $files): array
    {
        $out = [];
        foreach ($files as $file) {
            if (!isset($file['tmp_name'])) {
                continue;
            }

            if ($file['tmp_name'] === '') {
                continue;
            }

            $out[] = new ResolvedValue('FILES_TMPNAMES:' . $file['name'], $file['tmp_name']);
        }

        return $out;
    }

    /**
     * @param array<int, array{name: string, size?: int}> $files
     * @return array<int, ResolvedValue>
     */
    private function fileSizes(array $files): array
    {
        $out = [];
        foreach ($files as $file) {
            $out[] = new ResolvedValue('FILES_SIZES:' . $file['name'], (string) ($file['size'] ?? 0));
        }

        return $out;
    }

    /**
     * @return array<int, ResolvedValue>
     */
    private function xmlValues(string $xpath, RequestData $requestData): array
    {
        // An oversized body is not parsed at all rather than parsed truncated:
        // a prefix of a document is not a document, so DOM would reject it and
        // report nothing — with no record of why. Refusing up front keeps the
        // reason on the verdict.
        if ($this->maxRequestBodyBytes !== CrsConfig::UNLIMITED && strlen($requestData->body) > $this->maxRequestBodyBytes) {
            $this->recordTruncation('xml_body', 0, strlen($requestData->body));
            return [];
        }

        if (!$this->xmlBody instanceof XmlBody) {
            $this->xmlBody = new XmlBody($requestData);
        }

        $out = [];
        foreach ($this->xmlBody->xpath($xpath) as $i => $value) {
            $out[] = new ResolvedValue('XML:' . $xpath . '[' . $i . ']', $value);
        }

        return $out;
    }

    /**
     * @param array<int, string> $headers
     * @return array<int, ResolvedValue>
     */
    private function multipartHeaders(array $headers): array
    {
        $out = [];
        foreach ($headers as $i => $line) {
            $out[] = new ResolvedValue('MULTIPART_PART_HEADERS:' . $i, $line);
        }

        return $out;
    }

    /**
     * @param array<string, scalar|null> $flags
     * @return array<int, ResolvedValue>
     */
    private function multipartFlag(string $varName, array $flags): array
    {
        $key = strtoupper($varName);
        if (!array_key_exists($key, $flags) || $flags[$key] === null) {
            return [];
        }

        return [new ResolvedValue($key, (string) $flags[$key])];
    }

    private function filename(string $uri): string
    {
        $q = strpos($uri, '?');
        $path = $q === false ? $uri : substr($uri, 0, $q);
        return $path === '' ? '/' : $path;
    }

    /**
     * TX:<name> lookup.
     *
     * Rules address TX variables unprefixed (`TX:ANOMALY_SCORE`) while setvar
     * writes them prefixed (`setvar:'tx.anomaly_score=...'`), so a bare lookup
     * misses every variable the ruleset sets. Fall back to the `tx.` prefix,
     * mirroring RuleEvaluator::expandVariableRefs().
     *
     * A `/regex/` selector matches a family of names rather than one key —
     * CRS uses that to read back per-parameter counters it built with
     * setvar:'tx.paramcounter_%{MATCHED_VAR_NAME}=+1'.
     *
     * @return array<int, ResolvedValue>
     */
    private function txValues(?string $selector, bool $isRegex): array
    {
        if ($selector === null) {
            return [];
        }

        if ($isRegex) {
            return $this->txValuesMatching($selector);
        }

        $value = $this->txStore->get($selector);
        if ($value === null && !str_contains($selector, '.')) {
            $value = $this->txStore->get('tx.' . $selector);
        }

        return $value === null ? [] : [new ResolvedValue('TX:' . $selector, $value)];
    }

    /**
     * @return array<int, ResolvedValue>
     */
    private function txValuesMatching(string $pattern): array
    {
        $delimited = '#' . str_replace('#', '\\#', $pattern) . '#i';

        $out = [];
        foreach ($this->txStore->all() as $key => $value) {
            // Rules write `tx.foo` and match on `foo`, so compare unprefixed.
            $bare = preg_replace('/^tx\./', '', $key) ?? $key;
            if (@preg_match($delimited, $bare) === 1) {
                $out[] = new ResolvedValue('TX:' . $bare, $value);
            }
        }

        return $out;
    }

    /**
     * Flatten nested arrays one level so ARGS:user[email] resolves cleanly.
     * Deeper nesting falls back to serialised representation.
     *
     * @param array<int|string, mixed> $array
     * @return array<string, string>
     */
    private function flattenNested(array $array): array
    {
        $out = [];
        foreach ($array as $k => $v) {
            $out[(string) $k] = $this->stringify($v);
        }

        return $out;
    }

    private function matchesSelector(string $key, ?string $selector, bool $isRegex, bool $caseInsensitive = false): bool
    {
        if ($selector === null) {
            return true;
        }

        if ($isRegex) {
            return (bool) @preg_match('#' . str_replace('#', '\\#', $selector) . '#' . ($caseInsensitive ? 'i' : ''), $key);
        }

        return $caseInsensitive ? strcasecmp($key, $selector) === 0 : $key === $selector;
    }
}

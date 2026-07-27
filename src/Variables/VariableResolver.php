<?php

declare(strict_types=1);

namespace Kanopi\Crs\Variables;

use Kanopi\Crs\Body\XmlBody;
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

    public function __construct(
        private readonly TxStore $txStore,
        private readonly ?ResponseData $responseData = null,
    ) {
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

            if ($count) {
                $resolved[] = new ResolvedValue('&' . $collection . ($selector ? ':' . $selector : ''), (string) count($values));
                continue;
            }

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
            'REQUEST_BODY'     => [new ResolvedValue('REQUEST_BODY', $requestData->body)],
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
            'RESPONSE_BODY'    => $this->responseData instanceof \Kanopi\Crs\Request\ResponseData ? [new ResolvedValue('RESPONSE_BODY', $this->responseData->body)] : [],
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
                $out[] = new ResolvedValue(sprintf('%s:%s', $collection, $strKey), (string) $value);
            }
        }

        return $out;
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
                    $out[] = new ResolvedValue(sprintf('%s:%s', $collection, $strKey), (string) $sub);
                }
            } else {
                $out[] = new ResolvedValue(sprintf('%s:%s', $collection, $strKey), (string) $value);
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
            $out[(string) $k] = is_scalar($v) ? (string) $v : (json_encode($v) ?: '');
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

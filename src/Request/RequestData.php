<?php

declare(strict_types=1);

namespace Kanopi\Crs\Request;

/**
 * Framework-agnostic representation of an HTTP request used by the engine.
 *
 * Integrators adapt their framework's request object into this DTO so the
 * engine does not depend on Symfony, Laravel, PSR-7, etc.
 *
 * @phpstan-type FileUpload array{
 *     name: string,
 *     filename: string,
 *     mime?: string,
 *     size?: int,
 *     tmp_name?: string,
 *     content?: string
 * }
 */
final class RequestData
{
    /**
     * @param array<string, string|array<int|string, mixed>> $queryArgs Decoded GET params
     * @param array<string, string|array<int|string, mixed>> $postArgs Decoded POST params (form fields only)
     * @param array<string, string|array<int|string, mixed>> $cookies
     * @param array<string, string|array<int, string>> $headers Header name => value (lowercased keys recommended but not required)
     * @param array<int, FileUpload> $files Uploaded files metadata
     * @param array<string, scalar|null> $multipartFlags Optional CRS-922 anti-evasion flags (MULTIPART_*). Integrators that have a strict multipart parser available can populate these.
     * @param array<int, string> $multipartPartHeaders Raw `Header: value` lines from each multipart part (for MULTIPART_PART_HEADERS).
     * @param string|null $uniqueId Optional request ID (UNIQUE_ID variable).
     * @param string|null $bodyProcessor Name of the body processor that handled this request body (URLENCODED, MULTIPART, JSON, XML, RAW). Used by REQBODY_PROCESSOR variable.
     */
    public function __construct(
        public readonly string $method,
        public readonly string $uri,
        public readonly string $rawUri,
        public readonly string $queryString,
        public readonly string $protocol,
        public readonly string $remoteAddr,
        public readonly array $queryArgs = [],
        public readonly array $postArgs = [],
        public readonly array $cookies = [],
        public readonly array $headers = [],
        public readonly string $body = '',
        public readonly array $files = [],
        public readonly array $multipartFlags = [],
        public readonly array $multipartPartHeaders = [],
        public readonly ?string $uniqueId = null,
        public readonly ?string $bodyProcessor = null,
    ) {
    }

    /**
     * Convenience builder from PHP superglobals. Intended for CLI tools
     * and quick experimentation; production integrators should construct
     * RequestData directly from their framework's request object.
     */
    public static function fromGlobals(): self
    {
        $method   = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $uri      = $_SERVER['REQUEST_URI'] ?? '/';
        $query    = $_SERVER['QUERY_STRING'] ?? '';
        $protocol = $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1';
        $remote   = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with((string) $key, 'HTTP_')) {
                $name = strtolower(str_replace('_', '-', substr((string) $key, 5)));
                $headers[$name] = (string) $value;
            }
        }

        // PHP exposes these two without the HTTP_ prefix, so the loop above
        // misses them. Without Content-Length, CRS 920180 flags every POST as
        // a request-smuggling attempt; without Content-Type, the 920 body
        // processor rules cannot evaluate at all.
        foreach (['CONTENT_TYPE' => 'content-type', 'CONTENT_LENGTH' => 'content-length'] as $serverKey => $headerName) {
            if (isset($_SERVER[$serverKey]) && $_SERVER[$serverKey] !== '') {
                $headers[$headerName] ??= (string) $_SERVER[$serverKey];
            }
        }

        $body = '';
        if (in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            $body = (string) file_get_contents('php://input');
        }

        $files = [];
        foreach ($_FILES as $name => $info) {
            if (!is_array($info)) {
                continue;
            }

            $files[] = [
                'name'     => (string) $name,
                'filename' => (string) ($info['name']     ?? ''),
                'mime'     => (string) ($info['type']     ?? ''),
                'size'     => (int) (string) ($info['size'] ?? 0),
                'tmp_name' => (string) ($info['tmp_name'] ?? ''),
            ];
        }

        return new self(
            method: $method,
            uri: $uri,
            rawUri: $uri,
            queryString: $query,
            protocol: $protocol,
            remoteAddr: $remote,
            queryArgs: $_GET,
            postArgs: $_POST,
            cookies: $_COOKIE,
            headers: $headers,
            body: $body,
            files: $files,
            uniqueId: $_SERVER['UNIQUE_ID'] ?? null,
        );
    }

    public function header(string $name): ?string
    {
        $key = strtolower($name);
        foreach ($this->headers as $k => $v) {
            if (strtolower($k) === $key) {
                return is_array($v) ? implode(', ', $v) : $v;
            }
        }

        return null;
    }

    /**
     * Combined GET + POST args as a name-keyed map, for integrators that want
     * one bag to inspect.
     *
     * Lossy by construction: a name-keyed array cannot hold two parameters
     * with the same name, and the union below keeps the query value when both
     * bags carry one. That is fine for callers who want "the effective value
     * of parameter X", and wrong for rule evaluation, where a duplicated name
     * means two distinct values that both need inspecting. The engine does not
     * use this — VariableResolver resolves ARGS from queryArgs and postArgs
     * separately so neither value can hide the other.
     *
     * @return array<string, string|array<int|string, mixed>>
     */
    public function allArgs(): array
    {
        return $this->queryArgs + $this->postArgs;
    }

    /**
     * Basename of the URI path. Used by CRS rules that target REQUEST_BASENAME
     * (e.g. blocking access to backup-suffix filenames like `.bak`, `.old`).
     */
    public function basename(): string
    {
        $path = $this->uri;
        $q = strpos($path, '?');
        if ($q !== false) {
            $path = substr($path, 0, $q);
        }

        $slash = strrpos($path, '/');
        return $slash === false ? $path : substr($path, $slash + 1);
    }
}

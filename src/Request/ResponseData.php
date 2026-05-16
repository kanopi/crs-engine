<?php

declare(strict_types=1);

namespace Kanopi\Crs\Request;

/**
 * Companion DTO to RequestData carrying the HTTP response. Passed to
 * CrsEngine::evaluateResponse() after the application has rendered (but
 * before flushing to the client), so RESPONSE-* rules can scan for SQL
 * error messages, stack traces, PHP warnings, IIS error pages, and other
 * data-leakage signals.
 */
final class ResponseData
{
    /**
     * @param int $status HTTP status code (200, 500, ...)
     * @param string $protocol HTTP/1.1, HTTP/2, etc.
     * @param array<string, string|array<int, string>> $headers Header name => value
     * @param string $body Full response body as a single string.
     * @param string|null $contentType Convenience accessor. If null, derived from headers.
     */
    public function __construct(
        public readonly int $status,
        public readonly string $protocol = 'HTTP/1.1',
        public readonly array $headers = [],
        public readonly string $body = '',
        public readonly ?string $contentType = null,
    ) {
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

    public function effectiveContentType(): string
    {
        if ($this->contentType !== null) {
            return $this->contentType;
        }

        return (string) $this->header('Content-Type');
    }

    public function bodyLength(): int
    {
        return strlen($this->body);
    }
}

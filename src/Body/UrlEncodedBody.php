<?php

declare(strict_types=1);

namespace Kanopi\Crs\Body;

use Kanopi\Crs\Request\RequestData;

/**
 * Decodes an `application/x-www-form-urlencoded` body into ARGS.
 *
 * The same gap JsonBody closes, in the format most likely to hit it by
 * accident. PHP populates $_POST for urlencoded bodies, so RequestData::
 * fromGlobals() and any framework request object carry the arguments already —
 * but an integrator building RequestData from a PSR-7 request does not
 * necessarily, because getParsedBody() returns null unless something populated
 * it. The result was 0 of 15 rules matching an attack that scores 15 the moment
 * postArgs is set, with nothing anywhere to say so.
 *
 * parse_str is deliberately the parser here rather than a hand-rolled one. It
 * mangles names the way PHP does — `a.b` becomes `a_b` — and since the
 * application receiving this request is a PHP application reading $_POST, that
 * mangling is what the application will see too. Matching it is the point: a
 * more "correct" parser would disagree with the app and reintroduce the
 * differential this whole path is trying to avoid.
 */
final class UrlEncodedBody
{
    /** @var array<string, string|array<int|string, mixed>>|null */
    private ?array $args = null;

    public function __construct(private readonly RequestData $requestData)
    {
    }

    /**
     * Content-Type only — no shape sniffing.
     *
     * A urlencoded body is just text with `=` and `&` in it, and plenty of
     * bodies that are not forms contain both. Guessing would mean chopping a
     * plain-text body into nonsense arguments and inspecting the pieces, which
     * invents findings rather than finding them.
     */
    public function isLikelyUrlEncoded(): bool
    {
        if ($this->requestData->body === '') {
            return false;
        }

        return str_contains(
            strtolower((string) $this->requestData->header('Content-Type')),
            'application/x-www-form-urlencoded'
        );
    }

    /**
     * @return array<string, string|array<int|string, mixed>>
     */
    public function args(): array
    {
        if ($this->args !== null) {
            return $this->args;
        }

        if (!$this->isLikelyUrlEncoded()) {
            return $this->args = [];
        }

        $parsed = [];
        parse_str($this->requestData->body, $parsed);

        /** @var array<string, string|array<int|string, mixed>> $parsed */
        return $this->args = $parsed;
    }
}

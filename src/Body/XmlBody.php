<?php

declare(strict_types=1);

namespace Kanopi\Crs\Body;

use Kanopi\Crs\Request\RequestData;

/**
 * Lazy XML body parser used by VariableResolver to evaluate XML: targets.
 * Parses once per request, caches the DOMDocument, and runs XPath queries
 * against it. Defends against XXE by disabling external entity loading
 * before parsing.
 */
final class XmlBody
{
    private ?\DOMDocument $domDocument = null;

    private bool $attempted = false;

    public function __construct(private readonly RequestData $requestData)
    {
    }

    public function isLikelyXml(): bool
    {
        $contentType = strtolower((string) $this->requestData->header('Content-Type'));
        if (str_contains($contentType, 'xml')) {
            return true;
        }

        $body = ltrim($this->requestData->body);
        return $body !== '' && $body[0] === '<' && !str_contains($body, '<html');
    }

    public function document(): ?\DOMDocument
    {
        if ($this->attempted) {
            return $this->domDocument;
        }

        $this->attempted = true;

        if ($this->requestData->body === '' || !$this->isLikelyXml()) {
            return null;
        }

        $previousErrors = libxml_use_internal_errors(true);
        libxml_set_external_entity_loader(static fn () => null);

        $domDocument = new \DOMDocument();
        $loaded = @$domDocument->loadXML($this->requestData->body, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);

        libxml_clear_errors();
        libxml_use_internal_errors($previousErrors);

        $this->domDocument = $loaded ? $domDocument : null;
        return $this->domDocument;
    }

    /**
     * Evaluate an XPath expression against the parsed XML body.
     *
     * Returns one string per matched node (textContent for element nodes,
     * nodeValue for attributes / text nodes). Returns empty when the body
     * is not XML, is malformed, or the XPath fails to evaluate.
     *
     * @return array<int, string>
     */
    public function xpath(string $expression): array
    {
        $doc = $this->document();
        if (!$doc instanceof \DOMDocument) {
            return [];
        }

        $domxPath = new \DOMXPath($doc);
        $nodes = @$domxPath->query($expression === '' ? '//*' : $expression);
        if ($nodes === false) {
            return [];
        }

        $out = [];
        foreach ($nodes as $node) {
            $value = $node instanceof \DOMNode ? $node->textContent : '';
            if ($value !== '') {
                $out[] = $value;
            }
        }

        return $out;
    }
}

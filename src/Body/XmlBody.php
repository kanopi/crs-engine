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

        // XXE defence is the flag set, not an entity-loader override.
        //
        // libxml only substitutes entities when LIBXML_NOENT is passed, and we
        // deliberately do not pass it, so `<!ENTITY x SYSTEM "file:///...">`
        // never resolves here — even if the host application has installed a
        // permissive loader of its own. LIBXML_NONET blocks network fetches on
        // top of that. XmlBodyGlobalStateTest proves both, and will fail if
        // anyone adds LIBXML_NOENT to the call below.
        //
        // This used to also install a deny-everything entity loader. That is
        // process-global and, because libxml_set_external_entity_loader()
        // returns bool rather than the previous resolver, cannot be restored
        // at all before libxml_get_external_entity_loader() lands in PHP 8.4.
        // It silently disabled external entities for the host's own XSLT, DTD
        // validation and SOAP work for the life of the worker. Since the flags
        // already cover us, the fix is to not touch the global at all.
        //
        // libxml_use_internal_errors() is different: it returns the previous
        // value, so it can be restored honestly, and it is needed to keep
        // malformed request bodies out of the host's error handler.
        $previousErrors = libxml_use_internal_errors(true);

        try {
            $domDocument = new \DOMDocument();
            $loaded = @$domDocument->loadXML($this->requestData->body, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previousErrors);
        }

        $this->domDocument = $loaded ? $domDocument : null;
        return $this->domDocument;
    }

    /**
     * Evaluate an XPath expression against the parsed XML body.
     *
     * Returns one string per matched node, using textContent throughout —
     * which is the value for attribute and text nodes too, so no special case
     * is needed. Returns empty when the body is not XML, is malformed, or the
     * XPath fails to evaluate.
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

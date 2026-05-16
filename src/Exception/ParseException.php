<?php

declare(strict_types=1);

namespace Kanopi\Crs\Exception;

class ParseException extends CrsEngineException
{
    public function __construct(
        string $message,
        public readonly ?string $sourceFile = null,
        public readonly ?int $sourceLine = null,
        ?\Throwable $previous = null
    ) {
        $location = $sourceFile !== null
            ? sprintf(' [%s:%d]', $sourceFile, $sourceLine ?? 0)
            : '';
        parent::__construct($message . $location, 0, $previous);
    }
}

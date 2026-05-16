<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

interface OperatorInterface
{
    public function name(): string;

    /**
     * Evaluate the operator. $argument is the static operand parsed from
     * the rule (e.g. the regex for @rx, the phrase list for @pm).
     * $value is the transformed runtime value.
     */
    public function evaluate(string $argument, string $value): OperatorMatch;
}
